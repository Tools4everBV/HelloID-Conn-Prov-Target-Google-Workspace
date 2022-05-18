#region Initialize default properties
$c = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
$pRef = $entitlementContext | ConvertFrom-json

$success = $True
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()
$dynamicPermissions = [Collections.Generic.List[PSCustomObject]]::new()

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#region Supporting Functions
function Get-GoogleAccessToken() {
    ### exchange the refresh token for an access token
    $requestUri = "https://www.googleapis.com/oauth2/v4/token"
    $refreshTokenParams = @{
        client_id     = $c.clientId;
        client_secret = $c.clientSecret;
        redirect_uri  = $c.redirectUri;
        refresh_token = $c.refreshToken;
        grant_type    = "refresh_token"; # Fixed value
    };
    $response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $refreshTokenParams -Verbose:$false
    $accessToken = $response.access_token
    #Add the authorization header to the request
    $authorization = [ordered]@{
        Authorization  = "Bearer $($accesstoken)";
        'Content-Type' = "application/json; charset=utf-8";
        Accept         = "application/json";
    }
    $authorization
}
#endregion Supporting Functions

#region Change mapping here
$desiredPermissions = @{};
foreach ($contract in $p.Contracts) {
    Write-Verbose ("Contract in condition: {0}" -f $contract.Context.InConditions)
    if (( $contract.Context.InConditions) ) {
        # Get the authorization header
        $authorization = Get-GoogleAccessToken

        # Get Group from Google
        $splatParams = @{
            Body    = @{
                customer = "my_customer"
                # query = "description:$($permission.Name)"
            }
            URI     = "https://www.googleapis.com/admin/directory/v1/groups"
            Method  = 'GET'
            Headers = $authorization 
            Verbose = $False
        }
        $groupsResponse = Invoke-RestMethod @splatParams

        $description = $contract.Costcenter.Code
        $targetGroup = $null
        $targetGroup = $groupsResponse.groups | Where-Object { $_.description -Like "*$description*" }

        if ($null -eq $targetGroup) {
            throw "No Group found with description like *$description*"
        }
        elseif ($targetGroup.count -eq 1) {
            $group_DisplayName = $targetGroup.Name
            $group_ObjectGUID = $targetGroup.id
            $desiredPermissions["$($group_DisplayName)"] = $group_ObjectGUID          
        }
        elseif ($targetGroup.count -gt 1) {
            Write-Verbose "Multiple Groups found with description like *$description*. Adding all to desired permissions."

            foreach ($group in $targetGroup) {
                $group_DisplayName = $group.Name
                $group_ObjectGUID = $group.id
                $desiredPermissions["$($group_DisplayName)"] = $group_ObjectGUID
            }

            ### Example: Throw error when multiple groups found 
            # throw "Multiple Groups found with description like *$description*. Please correct this so the description is unique."
        }
    }
}

Write-Information ("Desired Permissions: {0}" -f ($desiredPermissions.keys | ConvertTo-Json))
#endregion Change mapping here

#region Execute
# Operation is a script parameter which contains the action HelloID wants to perform for this permission
# It has one of the following values: "grant", "revoke", "update"
$o = $operation | ConvertFrom-Json

if ($dryRun -eq $True) {
    # Operation is empty for preview (dry run) mode, that's why we set it here.
    $o = "grant"
}

Write-Verbose ("Existing Permissions: {0}" -f $entitlementContext)
$currentPermissions = @{}
foreach ($permission in $pRef.CurrentPermissions) {
    $currentPermissions[$permission.DisplayName] = $permission.Reference.Id
}

# Get the authorization header
$authorization = Get-GoogleAccessToken

# Get User Primary Email:
$splatParams = @{
    Uri     = "https://www.googleapis.com/admin/directory/v1/users/$aRef"
    Method  = 'GET'
    Headers = $authorization 
    Verbose = $False
}
try {
    $userResponse = Invoke-RestMethod @splatParams
    $userPrimaryEmail = $userResponse[0].primaryEmail
}
catch {
    write-warning "Target Google Account does not Exist: $aRef"
}

# Compare desired with current permissions and grant permissions
foreach ($permission in $desiredPermissions.GetEnumerator()) {
    $dynamicPermissions.Add([PSCustomObject]@{
            DisplayName = $permission.Name
            Reference   = [PSCustomObject]@{ Id = $permission.Value }
        })

    if (-Not $currentPermissions.ContainsKey($permission.Value)) {
        # Add user to Membership
        if (-Not($dryRun -eq $True)) {
            try {
                $account = [PSCustomObject]@{
                    email = $userPrimaryEmail
                    role  = "MEMBER"
                }

                $splatParams = @{
                    Uri     = "https://www.googleapis.com/admin/directory/v1/groups/$($permission.Value)/members"
                    Body    = [System.Text.Encoding]::UTF8.GetBytes(($account | ConvertTo-Json))
                    Method  = 'POST'
                    Headers = $authorization
                }
                
                Write-Verbose "Adding user: $($userPrimaryEmail) ($($aRef)) to group: $($permission.Name) ($($permission.Value))"
                $addMembershipResponse = Invoke-RestMethod @splatParams

                $success = $true
                $auditLogs.Add(
                    [PSCustomObject]@{
                        Action  = "GrantDynamicPermission"
                        Message = "Successfully granted $($userPrimaryEmail) ($($aRef)) to group $($permission.Name) ($($permission.Value))"
                        IsError = $false
                    }
                )
            }
            catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 409) {
                    $success = $true
                    Write-Information "Successfully granted $($userPrimaryEmail) ($($aRef)) to group $($permission.Name) ($($permission.Value)) (already a member)"
                }
                else {
                    $success = $false
                    $auditLogs.Add(
                        [PSCustomObject]@{
                            Action  = "GrantDynamicPermission"
                            Message = "Failed to grant $($userPrimaryEmail) ($($aRef)) to group $($permission.Name) ($($permission.Value))"
                            IsError = $true
                        }
                    )
                    Write-Warning $_
                }
            }           
        }
    }    
}

# Compare current with desired permissions and revoke permissions
$newCurrentPermissions = @{}
foreach ($permission in $currentPermissions.GetEnumerator()) {    
    if (-Not $desiredPermissions.ContainsKey($permission.Value)) {
        # Revoke Membership
        if (-Not($dryRun -eq $True)) {

            try {
                $splatParams = @{
                    Uri         = "https://www.googleapis.com/admin/directory/v1/groups/$($permission.Value)/members/$($aRef)"
                    Method      = 'DELETE' 
                    Headers     = $authorization
                    ErrorAction = 'Stop'
                }
                Write-Verbose "Removing user: $($userPrimaryEmail) ($($aRef)) from group: $($permission.Name) ($($permission.Value))"
                $removeMembershipResponse = Invoke-RestMethod @splatParams

                $success = $true
                $auditLogs.Add(
                    [PSCustomObject]@{
                        Action  = "RevokeDynamicPermission"
                        Message = "Successfully revoked $($userPrimaryEmail) ($($aRef)) from group $($permission.Name) ($($permission.Value))"
                        IsError = $false
                    }
                )
            }
            catch {
                if ($_.Exception.Response.StatusCode -eq 'NotFound') {
                    $success = $true
                    Write-Information "Successfully revoked $($userPrimaryEmail) ($($aRef)) from group $($permission.Name) ($($permission.Value)) (user not found in group)"
                }
                else {
                    $success = $false
                    $auditLogs.Add(
                        [PSCustomObject]@{
                            Action  = "RevokeDynamicPermission"
                            Message = "Failed to revoke $($userPrimaryEmail) ($($aRef)) from group $($permission.Name) ($($permission.Value))"
                            IsError = $true
                        }
                    )
    
                    Write-Warning $_
                }
            }
        }
    }
    else {
        $newCurrentPermissions[$permission.Name] = $permission.Value
    }
}

# Update current permissions
<# Updates not needed for Group Memberships.
if ($o -eq "update") {
    foreach($permission in $newCurrentPermissions.GetEnumerator()) {    
        $auditLogs.Add([PSCustomObject]@{
            Action = "UpdateDynamicPermission"
            Message = "Updated access to department share $($permission.Value)"
            IsError = $False
        })
    }
}
#>
#endregion Execute

#region Build up result
$result = [PSCustomObject]@{
    Success            = $success;
    DynamicPermissions = $dynamicPermissions;
    AuditLogs          = $auditLogs;
};
Write-Output $result | ConvertTo-Json -Depth 10;
#endregion Build up result