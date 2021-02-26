$config = ConvertFrom-Json $configuration;
 
#Initialize default properties
$success = $False;
$auditMessage = "Membership for person $($p.DisplayName) not added successfully";
 
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
        Write-Verbose -Verbose "$($userResponse[0].primaryEmail)";

        if($pRef.Type -eq "Group")
        {
            Write-Verbose -Verbose "Applying Group Permission"
            
            
            $account = @{
                        email = $userResponse[0].primaryEmail;
                        role = "MEMBER";
            }

            $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/groups/$($pRef.Id)/members" -Body ($account | ConvertTo-Json) -Method POST -Headers $authorization
            $success = $True;
            $auditMessage = " successfully";
        }
        elseif($pRef.Type -eq "License")
        {
            Write-Verbose -Verbose "Applying License Permission"

            $account = @{   
                            userId = $userResponse[0].primaryEmail;
            }
            Write-Verbose -Verbose "https://licensing.googleapis.com/apps/licensing/v1/product/$($pRef.ProductId)/sku/$($pRef.SkuId)/user";
            $response = Invoke-RestMethod -Uri "https://licensing.googleapis.com/apps/licensing/v1/product/$($pRef.ProductId)/sku/$($pRef.SkuId)/user" -Body ($account | ConvertTo-Json) -Method POST -Headers $authorization
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
            Write-Verbose -Verbose "Status Code: $($_.Exception.Response.StatusCode.value__)"
            Write-Verbose -Verbose ($_ | ConvertFrom-Json).error.message;
            if($_.Exception.Response.StatusCode.value__ -eq 409)
            {
                $success = $True;
                $auditMessage = " successfully (already exists)";
            }
            if($_.Exception.Response.StatusCode.value__ -eq 412)
            {
                
                if( ($_ | ConvertFrom-Json).error.message -like "*User already has a license for the specified product and SKU*" )
                {
                    $success = $true;
                    $auditMessage = " successfully (already assigned)";
                }
                else
                {
                    $success = $false;
                    $auditMessage = " : General error $($_)";
                }
                
            }
            else
            {
                $auditMessage = " : General error $($_)";
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