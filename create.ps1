$clientId = "<put your client id here>"
$clientSecret = "<put your client secret here>"
$redirectUri = "http://localhost/oauth2callback"
$refreshToken = "<put your refreshtoken here>"
 
#Initialize default properties
$success = $False;
$p = $person | ConvertFrom-Json
$auditMessage = "Account for person " + $p.DisplayName + " not created successfully";
 
$defaultPassword = "Welkom01!";
$defaultDomain = "yourdomain.com";
 
#Change mapping here
#For all of the supported attributes please check https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
$account = [PSCustomObject]@{
    primaryEmail = $p.Contact.Business.Email.split("@")[0] + "@" + $defaultDomain
    name = @{
                givenName = $p.Name.NickName
                familyName = $p.Name.FamilyName
                fullName = ($p.Name.NickName + " " + $p.Name.FamilyName)
            }
    externalIds = @{
                value = $p.ExternalId
                type = "custom"
                customType = "employee"
            }
    password = $defaultPassword
    suspended = $True
}
 
try{
    if(-Not($dryRun -eq $True)){
        ### exchange the refresh token for an access token
        $requestUri = "https://www.googleapis.com/oauth2/v4/token"
         
        $refreshTokenParams = @{
             client_id=$clientId;
             client_secret=$clientSecret;
             redirect_uri=$redirectUri;
             refresh_token=$refreshToken;
             grant_type="refresh_token"; # Fixed value
        };
        $response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $refreshTokenParams -Verbose:$false
        $accessToken = $response.access_token
                
        #Add the authorization header to the request
        $authorization = @{
            Authorization = "Bearer $accesstoken";
            'Content-Type' = "application/json";
            Accept = "application/json";
        }
        $body = $account | ConvertTo-Json -Depth 10
        $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$aRef" -Method POST -Headers $authorization -Body $body -Verbose:$false
        $aRef = $response.id
    }
    $success = $True;
    $auditMessage = " successfully"; 
}catch{
    if(-Not($_.Exception.Response -eq $null)){
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $errResponse = $reader.ReadToEnd();
        $auditMessage = " : ${errResponse}";
    }else {
        $auditMessage = " : General error";
    } 
}
 
#build up result
$result = [PSCustomObject]@{
    Success= $success;
    AccountReference= $aRef;
    AuditDetails=$auditMessage;
    Account= $account;
};
  
Write-Output $result | ConvertTo-Json -Depth 10;
