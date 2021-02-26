#2020-11-17
$config = ConvertFrom-Json $configuration;

#Initialize default properties
$success = $False;
$auditMessage = "Membership for person $($p.DisplayName) not removed successfully";
 
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
                Authorization = "Bearer $accesstoken";
                'Content-Type' = "application/json";
                Accept = "application/json";
            }
        #Get Member Email
        $userResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" -Method GET -Headers $authorization -Verbose:$false
 
        if($pRef.Type -eq "Group")
        {
            $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/groups/$($pRef.Id)/members/$($userResponse[0].primaryEmail)" -Method DELETE -Headers $authorization
            $success = $True;
            $auditMessage = " successfully";
        }
        elseif($pRef.Type -eq "License")
        {
             $uri = "https://licensing.googleapis.com/apps/licensing/v1/product/$($pRef.ProductId)/sku/$($pRef.SkuId)/user/$($userResponse[0].primaryEmail)";
             Write-Verbose -Verbose $uri
             $response = Invoke-RestMethod -Uri $uri -Method DELETE -Headers $authorization -ContentType "application/json; charset=utf-8";
             $success = $True;
             $auditMessage = " successfully";
        }
        else
        {
            $success = $False;
            $auditMessage = " not successfully";
        }
    }catch
    {
            if($_.Exception.Response.StatusCode.value__ -eq 412)
            {
                $success = $True;
                $auditMessage = " successfully (Auto License un-assignment is not allowed.)";
            }
            else
            {
                $auditMessage = " : General error $($_)";
                Write-Error -Verbose $_; 
            }
    }
}

 
#build up result
$result = [PSCustomObject]@{
    AccountReference = $pRef
    Success= $success;
    AuditDetails=$auditMessage;
};
 
Write-Output $result | ConvertTo-Json -Depth 10;