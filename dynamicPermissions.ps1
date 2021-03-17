#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-json

$success = $False
$auditLogs = New-Object Collections.Generic.List[PSCustomObject];
$dynamicPermissions = New-Object Collections.Generic.List[PSCustomObject];
#endregion Initialize default properties

#region Support Functions
function Get-GoogleAccessToken() {
    ### exchange the refresh token for an access token
    $requestUri = "https://www.googleapis.com/oauth2/v4/token"

    $refreshTokenParams = @{
            client_id=$config.clientId;
            client_secret=$config.clientSecret;
            redirect_uri=$config.redirectUri;
            refresh_token=$config.refreshToken;
            grant_type="refresh_token"; # Fixed value
    };
    $response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $refreshTokenParams -Verbose:$false
    $accessToken = $response.access_token

    #Add the authorization header to the request
    $authorization = [ordered]@{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
    $authorization
}
#endregion Support Functions

#region Change mapping here
    $groupName = "GroupName";
    $groupEmail = $groupName + "@domain.com";
    $groupDescription = "";

    $desiredPermissions = @{};
    $desiredPermissions[$groupName] = $groupName;
#endregion Change mapping here

#region Execute
    #Add the authorization header to the request
    $authorization = Get-GoogleAccessToken

    # Operation is a script parameter which contains the action HelloID wants to perform for this permission
    # It has one of the following values: "grant", "revoke", "update"
    $o = $operation | ConvertFrom-Json;

    if($dryRun -eq $True) {
        # Operation is empty for preview (dry run) mode, that's why we set it here.
        $o = "grant";
    }

    $currentPermissions = @{};
    foreach($permission in $pRef.CurrentPermissions) {
        $currentPermissions[$permission.Reference.Id] = $permission.DisplayName;
    }

    #Get Member Email
    $userResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" -Method GET -Headers $authorization -Verbose:$false

    # Verify that the target group exists
    try {
        $groupResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/groups/$groupEmail" -Method GET -Headers $authorization -Verbose:$false
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq "404") {
            $newGroup = @{
            email = $groupEmail
            name = $groupName
            description = $groupDescription
            }

            # Create the group, because it doesn't exist
            if(-Not($dryRun -eq $True)){
            $body = $newGroup | ConvertTo-Json -Depth 10
            $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/groups" -Method POST -Headers $authorization -Body $body -Verbose:$false
            $gRef = $response.id

            Write-Verbose -Verbose "Created group $groupEmail successfully."

            } else {
                Write-Verbose -Verbose "Dry run. Would have created group $groupEmail during live run."
            }
        }
    }

    # Compare desired with current permissions and grant permissions
    foreach($permission in $desiredPermissions.GetEnumerator()) {
        $dynamicPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value;
                Reference = [PSCustomObject]@{ Id = $permission.Name };
        });

        if(-Not $currentPermissions.ContainsKey($permission.Name))
        {
            $account = @{
                        email = $userResponse[0].primaryEmail;
                        role = "MEMBER";
            }

            try {
                if(-Not($dryRun -eq $True)){
                    $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/groups/$groupEmail/members" -Body ($account | ConvertTo-Json) -Method POST -Headers $authorization
                    $success = $True;
                }
                $auditLogs.Add([PSCustomObject]@{
                    Action = "GrantDynamicPermission";
                    Message = "Granted access to group $($permission.Value)";
                    IsError = $False;
                });
            } catch {
                $auditLogs.Add([PSCustomObject]@{
                    Action = "GrantDynamicPermission";
                    Message = "Failed to add member to group $($permission.Value) with exception $($_.Exception)";
                    IsError = $True;
                });
            }
        }
    }

    # Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{};
    foreach($permission in $currentPermissions.GetEnumerator()) {
        if(-Not $desiredPermissions.ContainsKey($permission.Name))
        {
            try {
                if(-Not($dryRun -eq $True)){
                    $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/groups/$groupEmail/members/$($userResponse[0].primaryEmail)" -Method DELETE -Headers $authorization
                    $success = $True;
                }
                $auditLogs.Add([PSCustomObject]@{
                    Action = "RevokeDynamicPermission";
                    Message = "Revoked access to group $($permission.Value)";
                    IsError = $False;
                });
            } catch {
                $auditLogs.Add([PSCustomObject]@{
                    Action = "RevokeDynamicPermission";
                    Message = "Failed to remove member from group $($permission.Value) with exception $($_.Exception)";
                    IsError = $True;
                });
            }
        } else {
            $newCurrentPermissions[$permission.Name] = $permission.Value;
        }
    }

    $success = $True;
#endregion Execute

#region Build up result
$result = [PSCustomObject]@{
    Success = $success;
    DynamicPermissions = $dynamicPermissions;
    AuditLogs = $auditLogs;
};
Write-Output $result | ConvertTo-Json -Depth 10;
#endregion Build up result