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
        'Content-Type' = "application/json; charset=utf-8";
        Accept = "application/json";
    }
    $authorization
}
#endregion Support Functions

#region Execute
try{
    if(-Not($dryRun -eq $True)){
        #Add the authorization header to the request
        $authorization = Get-GoogleAccessToken

        # Get Previous Account
        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)"
            Method = 'GET'
            Headers = $authorization
            Verbose = $False
        }
        $previousAccount = Invoke-RestMethod @splat

        #Delete Account
        $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" -Method DELETE -Headers $authorization -Verbose:$false

        $auditLogs.Add([PSCustomObject]@{
            Action = "DeleteAccount"
            Message = "Deleted account with PrimaryEmail $($previousAccount.primaryEmail)"
            IsError = $false;
        });
    }
    $success = $True;

}catch{
    $auditLogs.Add([PSCustomObject]@{
        Action = "Delete Account"
        Message = "Error deleting account with PrimaryEmail $($previousAccount.primaryEmail) - Error: $($_)"
        IsError = $true;
    });
    Write-Error -Verbose $_;
}
#endregion Execute

#region Build up result
$result = [PSCustomObject]@{
	Success = $success
	AccountReference = $aRef
	AuditLogs = $auditLogs;
	Account = [PSCustomObject]@{}
	PreviousAccount = $previousAccount
}

Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion Build up result