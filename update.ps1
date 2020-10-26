#2020-10-26
$config = ConvertFrom-Json $configuration;
 
#Initialize default properties
$success = $False;
$p = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json;
$auditMessage = "Account for person $($p.DisplayName) not updated successfully";
 
#Change mapping here
#For all of the supported attributes please check https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
$account = [PSCustomObject]@{
    name = @{
                givenName = "$($p.Name.NickName)"
                familyName = "$($p.Name.FamilyName)"
                fullName = "$($p.Name.NickName) $($p.Name.FamilyName)"
            }
    externalIds =  @(@{
                        value = "$($p.ExternalId)"
                        type = "organization";
                    })
    organizations = @(@{
                        title = "$($p.primaryContract.Title.name)"
                        #department = "$($p.primaryContract.custom.TeamDesc)"
                        #costCenter = "$($p.primaryContract.costCenter.ExternalID)"
                    })
    orgUnitPath = "/Users"
}
 
try{
    if(-Not($dryRun -eq $True)){
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
        $authorization = @{
            Authorization = "Bearer $($accesstoken)";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }
        $body = $account | ConvertTo-Json -Depth 10
        $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" -Method PUT -Headers $authorization -Body $body -Verbose:$false
    }
    $success = $True;
    $auditMessage = " successfully";
}catch{
    Write-Error -Verbose $_; 
}
 
#build up result
$result = [PSCustomObject]@{
    Success= $success;
    AccountReference= $aRef;
    AuditDetails=$auditMessage;
    Account= $account;
};
  
Write-Output $result | ConvertTo-Json -Depth 10;
