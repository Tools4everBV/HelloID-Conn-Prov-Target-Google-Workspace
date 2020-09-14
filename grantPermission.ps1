$clientId = "CLIENTID"
$clientSecret = "CLIENT SECRET"
$redirectUri = "http://localhost/oauth2callback"
$refreshToken = "REFRESHTOKEN"
 
#Initialize default properties
$success = $False;
$auditMessage = "Membership for person " + $p.DisplayName + " not added successfully";
 
$p = $person | ConvertFrom-Json;
$m = $manager | ConvertFrom-Json;
$aRef = $accountReference | ConvertFrom-Json;
$mRef = $managerAccountReference | ConvertFrom-Json;
$pRef = $permissionReference | ConvertFrom-json;
 
if(-Not($dryRun -eq $True)) {
    try
    {
        $requestUri = "https://www.googleapis.com/oauth2/v4/token";
         
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
         
 
        #Get Member Email
        $userResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" -Method GET -Headers $authorization -Verbose:$false
 
         
        $account = @{
                    email = $userResponse[0].primaryEmail;
                    role = "MEMBER";
        }
 
        $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/groups/$($pRef.Id)/members" -Body ($account | ConvertTo-Json) -Method POST -Headers $authorization
        $success = $True;
        $auditMessage = " successfully";
    }catch
    {
            Write-Verbose -Verbose "Status Code: $($_.Exception.Response.StatusCode.value__)"
            if($_.Exception.Response.StatusCode.value__ -eq 409)
            {
                $success = $True;
                $auditMessage = " successfully (already exists)";
            }
            else
            {
                Write-Error -Verbose $_; 
           }
    }
}
 
 
 
#build up result
$result = [PSCustomObject]@{
    Success= $success;
    AuditDetails=$auditMessage;
    Account = $account;
};
 
Write-Output $result | ConvertTo-Json -Depth 10;  
