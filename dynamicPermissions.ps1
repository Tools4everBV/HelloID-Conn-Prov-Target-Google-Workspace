#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-Json

$currentPermissions = @{}
foreach($permission in $pRef.CurrentPermissions) {
    $currentPermissions[$permission.DisplayName] = $permission.Reference.Id
}

$success = $True
$auditLogs = New-Object Collections.Generic.List[PSCustomObject]
$dynamicPermissions = New-Object Collections.Generic.List[PSCustomObject]

# Operation is a script parameter which contains the action HelloID wants to perform for this permission
# It has one of the following values: "grant", "revoke", "update"
$o = $operation | ConvertFrom-Json

if($dryRun -eq $True) {
    # Operation is empty for preview (dry run) mode, that's why we set it here.
    $o = "grant"
}
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
    $response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $refreshTokenParams -Verbose:$False
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
$desiredPermissions = @{}
foreach($contract in $p.Contracts) {
    if($contract.Context.InConditions -OR ($dryRun -eq $True))
    {
        # Grades 7-12:  <Ordinal Grade>
        if($contract.custom.grade -match '^\d+$' -AND [int]$contract.custom.grade -ge 7)
        {
            $group_Name = "{0}th" -f [int]$contract.custom.grade
            $desiredPermissions[$group_Name] = $group_Name
            Write-Verbose -Verbose ("Defined Group:  {0}" -f $group_Name)
        }

        # <School Level>Internet
        $group_Name = "{0}Internet" -f $contract.custom.schoolLevel.replace("High","Highschool")
        $desiredPermissions[$group_Name] = $group_Name
        Write-Verbose -Verbose ("Defined Group:  {0}" -f $group_Name)
    }
}

Write-Verbose -Verbose ("Defined Permissions: {0}" -f ($desiredPermissions.keys | ConvertTo-Json))
#endregion Change mapping here

#region Execute
Write-Verbose -Verbose ("Existing Permissions: {0}" -f $permissionReference)

# Add the authorization header to the request
$authorization = Get-GoogleAccessToken

# Get User Primary Email:
    $splat = @{
        Uri = "https://www.googleapis.com/admin/directory/v1/users/{0}" -f $aRef
        Method = 'GET'
        Headers = $authorization 
        Verbose =$False
    }
    try{
        $userResponse = Invoke-RestMethod @splat
    }
    catch{
        write-warning ("Target Google Account does not Exist: {0}" -f $aRef)
    }

# Compare desired with current permissions and grant permissions
foreach($permission in $desiredPermissions.GetEnumerator()) {

    if(-Not $currentPermissions.ContainsKey($permission.Name))
    {
        $targetGroup = $null
        # Get Group from Google
        $splat = @{
            Body = @{
                customer = "my_customer"
                query = "Name={0}" -f $permission.Name
            }
            URI = "https://www.googleapis.com/admin/directory/v1/groups"
            Method = 'GET'
            Headers = $authorization 
            Verbose = $False
            }
        $groupResponse = Invoke-RestMethod @splat 
        if($groupResponse.groups)
        {
            $targetGroup = $groupResponse.groups[0]
            $permissionSuccess = $True
        } else {
            write-warning ("Unable to find target group: {0}" -f $permission.Name)
            <# Uncomment the following block to create the defined group.
            # Create the group, because it doesn't exist
            $newGroup = @{
                name = "{0}" -f $permission.Name
                email = "{0}@{1}" -f $permission.Name,$config.defaultDomain
                description = ""
            }

            if(-Not($dryRun -eq $True)){
                $splat = @{
                    Body = $newGroup | ConvertTo-Json -Depth 10
                    Uri = "https://www.googleapis.com/admin/directory/v1/groups" 
                    Method = 'POST' 
                    Headers = $authorization 
                    Verbose = $False
                }
                $targetGroup = Invoke-RestMethod @splat
                $permissionSuccess = $True

                Write-Information ("Created group {0} successfully." -f $permission.Name)
                $auditLogs.Add([PSCustomObject]@{
                    Action = "GrantDynamicPermission"
                    Message = "Created Group: {0}" -f $newGroup.email
                    IsError = -Not $permissionSuccess
                })
            } else {
                Write-Information ("Dry run. Would have created group {0} during live run." -f $permission.Name)
            }
            #>
            
            # If creating group, comment out the following Success variables
            $permissionSuccess = $False
            $success = $False
        }
        
        # Add Permission to return list of Dynamic Permissions.  
        #   Populate the ID with the ID of the target group (to be used with Revokes)
        $dynamicPermissions.Add([PSCustomObject]@{
            DisplayName = $permission.Name
            Reference = [PSCustomObject]@{ Id = $targetGroup.id }
        })
        # Add user to Membership
        if(-Not($dryRun -eq $True) -AND $null -ne $targetGroup)
        {
            $membership = @{
                email = $userResponse[0].primaryEmail
                role = "MEMBER"
            }

            try {
                if(-Not($dryRun -eq $True)){
                    $splat = @{
                        Uri = "https://www.googleapis.com/admin/directory/v1/groups/{0}/members" -f $targetGroup.id
                        Body = $membership | ConvertTo-Json
                        Method = 'POST'
                        Headers = $authorization
                    }
                    $response = Invoke-RestMethod @splat
                    $permissionSuccess = $True
                    Write-Verbose -Verbose ("Successfully Granted Permission to: {0}" -f $permission.Name)
                }

            } catch {
                Write-Information "Status Code: $($_.Exception.Response.StatusCode.value__)"
                Write-Information ($_ | ConvertFrom-Json).error.message;
                if($_.Exception.Response.StatusCode.value__ -eq 409)
                {
                    $permissionSuccess = $True;
                    Write-Information ("Membership for person {0} added to {1} (already exists)" -f $p.DisplayName,$pRef.DisplayName)
                }
                else
                {
                    $success = $False
                    $permissionSuccess = $False
                    # Log error for further analysis.  Contact Tools4ever Support to further troubleshoot
                    Write-Error ("Error Granting Permission for Group [{0}]:  {1}" -f $permission.Name, $_)
                }
            }
        }

        $auditLogs.Add([PSCustomObject]@{
            Action = "GrantDynamicPermission"
            Message = "Granted access to group $($permission.Value)";
            IsError = -NOT $permissionSuccess
        })
    }    
}

# Compare current with desired permissions and revoke permissions
$newCurrentPermissions = @{}
foreach($permission in $currentPermissions.GetEnumerator()) {    
    if(-Not $desiredPermissions.ContainsKey($permission.Name))
    {
        try {
            # Revoke Membership
            if(-Not($dryRun -eq $True)){
                $splat = @{
                    Uri = "https://www.googleapis.com/admin/directory/v1/groups/{0}/members/{1}" -f $permission.Value,$aRef
                    Method = 'DELETE' 
                    Headers = $authorization
                }
                $response = Invoke-RestMethod @splat
                $permissionSuccess = $True;
            }
        } catch {
            if($_.Exception.Response.StatusCode -eq 'NotFound')
            {
                $permissionSuccess = $True;
                Write-Warning ("User not found in target Group.  Membership not removed.")
            }
            else
            {
                $permissionSuccess = $False
                $success = $False
                # Log error for further analysis.  Contact Tools4ever Support to further troubleshoot.
                Write-Error ("Error Revoking Permission from Group [{0}]:  {1}" -f $permission.Name, $_)
            }
        }
        
        $auditLogs.Add([PSCustomObject]@{
            Action = "RevokeDynamicPermission"
            Message = "Revoked access to group: {0}" -f $permission.Name 
            IsError = -Not $permissionSuccess
        })
    } else {
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
    Success = $success
    DynamicPermissions = $dynamicPermissions
    AuditLogs = $auditLogs
}
Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion Build up result