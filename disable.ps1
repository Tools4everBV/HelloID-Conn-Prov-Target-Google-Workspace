#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json;

$success = $False
$auditLogs = New-Object Collections.Generic.List[PSCustomObject];
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
    $defaultOrgUnitPath = "/Users"

    #Target OrgUnitPath
    $calcOrgUnitPath = ("{0}/{1}" -f
        $defaultOrgUnitPath,
        $p.PrimaryContract.Department.ExternalID
        )
    Write-Information ("Target OU: {0}" -f $calcOrgUnitPath)

    #Change mapping here
    $account = @{
        suspended = $True
        orgUnitPath = $calcOrgUnitPath;
    }
#endregion Change mapping here
 
#region Execute
try{
    #Add the authorization header to the request
    $authorization = Get-GoogleAccessToken

    # Verify Target OU Exists.  Else, use Default OU
    $splat = @{
        Uri = ("https://www.googleapis.com/admin/directory/v1/customer/my_customer/orgunits{0}" -f $calcOrgUnitPath)
        Method = 'GET'
        Headers = $authorization
        Verbose = $False
        ErrorAction = 'Stop'
    }

    #API will error if target OU does not exist.
    try {
        $response = Invoke-RestMethod @splat
        $account.orgUnitPath = $calcOrgUnitPath
    }
    catch {
        Write-Information ("Target OU Not found.  Using Default OU: {0}" -f $defaultOrgUnitPath)
        $account.orgUnitPath = $defaultOrgUnitPath
    }

    #Send User Update
    if(-Not($dryRun -eq $True)) {
        # Get Previous Account
        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" 
            Method = 'GET'
            Headers = $authorization 
            Verbose = $False
        }
        $previousAccount = Invoke-RestMethod @splat

        $splat = @{
            body = ($account | ConvertTo-Json -Depth 10)
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" 
            Method = 'PUT'
            Headers = $authorization
            Verbose = $False
        }
        $updatedAccount = Invoke-RestMethod @splat
        #Write-Information ("Response: {0}" -f ($response | ConvertTo-Json -Depth 50))

        $auditLogs.Add([PSCustomObject]@{
            Action = "DisableAccount"
            Message = "Disabled/Updated account with PrimaryEmail $($updatedAccount.primaryEmail) in OrgUnit [$($updatedAccount.orgUnitPath)]"
            IsError = $false;
        });
    }
    else {
        $updatedAccount = $account;
    }

    $success = $True
}catch{
    $auditLogs.Add([PSCustomObject]@{
        Action = "DisableAccount"
        Message = "Error disabling/updating account with PrimaryEmail $($previousAccount.primaryEmail) - Error: $($_)"
        IsError = $true;
    });
    Write-Error $_
}
#endregion Execute

#region Build up result
$result = [PSCustomObject]@{
	Success = $success
	AccountReference = $aRef
	AuditLogs = $auditLogs;
	Account = $updatedAccount
	PreviousAccount = $previousAccount

    ExportData = [PSCustomObject]@{
        OrgUnitPath = $updatedAccount.orgUnitPath
    }
}
  
Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion Build up result