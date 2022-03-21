#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json

$success = $True
$auditLogs = [Collections.Generic.List[PSCustomObject]]@()

# Operation is a script parameter which contains the action HelloID wants to perform for this permission
# It has one of the following values: "grant", "revoke", "update"
$o = $operation | ConvertFrom-Json

# The permissionReference contains the Identification object provided in the retrieve permissions call
$pRef = $permissionReference | ConvertFrom-Json

# The entitlementContext contains the sub permissions (Previously the $permissionReference variable)
$eRef = $entitlementContext | ConvertFrom-Json

$currentPermissions = @{}
foreach($permission in $eRef.CurrentPermissions) {
    $currentPermissions[$permission.DisplayName] = $permission.Reference.Id
}

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$subPermissions = [Collections.Generic.List[PSCustomObject]]@()

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
if ($o -ne "revoke")
{
    # Contract Based Logic:
    foreach($contract in $p.Contracts) {
        if(($contract.Context.InConditions) -OR ($dryRun -eq $True))
        {
            # Note:  Generate Group Email (without the @<domain>).  Group Name lookup does not work well with Google.
            # <Group Prefix>.students.<grade>
            # P => PreK, 01-12 - Drop leading 0's
            if(-NOT [string]::IsNullOrWhiteSpace($contract.custom.GroupPrefix))
            {
                $grade = $p.Custom.Grade -Replace '^0','' -Replace 'P','PreK'
                $group_email = "{0}.students.{1}" -f $contract.Custom.GroupPrefix,$grade
                $desiredPermissions[$group_email] = $group_email
            }    
        }
    }
}

Write-Information ("Defined Permissions: {0}" -f ($desiredPermissions.keys | ConvertTo-Json))
#endregion Change mapping here

#region Execute
Write-Information ("Existing Permissions: {0}" -f $entitlementContext)

# Get the authorization header
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
                query    = "Email:{0}@*" -f $permission.Name
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
			$permissionSuccess = $False
			$success = $False
	        
        }

        # Add Permission to return list of Dynamic Permissions.  
        #   Populate the ID with the ID of the target group (to be used with Revokes)
        $subPermissions.Add([PSCustomObject]@{
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

            try
            {
                $splat = @{
                    Uri = "https://www.googleapis.com/admin/directory/v1/groups/{0}/members" -f $targetGroup.id
                    Body = $membership | ConvertTo-Json
                    Method = 'POST'
                    Headers = $authorization
                    ErrorAction = 'Stop'
                }
                $response = Invoke-RestMethod @splat
                $permissionSuccess = $True                
                Write-Information ("Successfully Granted Permission to: {0}" -f $permission.Name)
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
            Action = "GrantPermission"
            Message = "Granted access to group: {0}" -f $permission.Value
            IsError = -NOT $permissionSuccess
        })
    }    
}

# Compare current with desired permissions and revoke permissions
$newCurrentPermissions = @{}
foreach($permission in $currentPermissions.GetEnumerator()) {    
    if(-Not $desiredPermissions.ContainsKey($permission.Name) -AND $permission.Name -ne "No Groups Defined")
    {
        # Revoke Membership
        if(-Not($dryRun -eq $True))
        {
            try
            {
                $splat = @{
                    Uri = "https://www.googleapis.com/admin/directory/v1/groups/{0}/members/{1}" -f $permission.Value,$aRef
                    Method = 'DELETE' 
                    Headers = $authorization
                    ErrorAction = 'Stop'
                }
                $response = Invoke-RestMethod @splat
                $permissionSuccess = $True
            }
            catch
            {
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
        }
        
        $auditLogs.Add([PSCustomObject]@{
            Action = "RevokePermission"
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
            Action = "UpdatePermission"
            Message = "Updated access to department share $($permission.Value)"
            IsError = $False
        })
    }
}
#>

# Handle case of empty defined dynamic permissions.  Without this the entitlement will error.
if ($o -match "update|grant" -AND $subPermissions.count -eq 0)
{
    $subPermissions.Add([PSCustomObject]@{
            DisplayName = "No Groups Defined"
            Reference = [PSCustomObject]@{ Id = "No Groups Defined" }
    })
}

#endregion Execute

#region Build up result
$result = [PSCustomObject]@{
    Success = $success
    SubPermissions = $subPermissions
    AuditLogs = $auditLogs
}
Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion Build up result