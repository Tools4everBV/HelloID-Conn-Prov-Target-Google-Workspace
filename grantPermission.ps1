#2021-02-02 - Google Grant Permission
$config = ConvertFrom-Json $configuration

#Initialize default properties
$p = $person | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-json

$success = $False
$auditMessage = "Membership for person $($p.DisplayName) added to $($pRef.DisplayName)"

#Support Functions
function google-refresh-accessToken()
{
    ### exchange the refresh token for an access token
    $requestUri = "https://www.googleapis.com/oauth2/v4/token"
        
    $refreshTokenParams = @{
            client_id=$config.clientId
            client_secret=$config.clientSecret
            redirect_uri=$config.redirectUri
            refresh_token=$config.refreshToken
            grant_type="refresh_token" # Fixed value
    };
    $response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $refreshTokenParams -Verbose:$false
    $accessToken = $response.access_token
            
    #Add the authorization header to the request
    $authorization = [ordered]@{
        Authorization = "Bearer $accesstoken"
        'Content-Type' = "application/json"
        Accept = "application/json"
    }
    $authorization
}

if(-Not($dryRun -eq $True)) {
    try
    {
        $authorization = google-refresh-accessToken

        #Get Member Email
        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" 
            Method = 'GET'
            Headers = $authorization 
            Verbose = $False
        }
        $userResponse = Invoke-RestMethod @splat
        Write-Information "$($userResponse[0].primaryEmail)"

        if($pRef.Type -eq "Group")
        {
            Write-Information "Applying Group Permission"
            
            $account = @{
                        email = $userResponse[0].primaryEmail
                        role = "MEMBER"
            }
            $splat = @{
                Uri = "https://www.googleapis.com/admin/directory/v1/groups/$($pRef.Id)/members" 
                Body = @{
                    email = $userResponse[0].primaryEmail
                    role = "MEMBER"
                }
                Method = 'POST'
                Headers = $authorization
            }
            $response = Invoke-RestMethod @splat
            $success = $True
            $auditMessage += " successfully"
        }
        elseif($pRef.Type -eq "License")
        {
            Write-Information "Applying License Permission"

            $account = @{   
                userId = $userResponse[0].primaryEmail
            }
            #Write-Information "https://licensing.googleapis.com/apps/licensing/v1/product/$($pRef.ProductId)/sku/$($pRef.SkuId)/user"
            $splat = @{
                Uri = "https://licensing.googleapis.com/apps/licensing/v1/product/$($pRef.ProductId)/sku/$($pRef.SkuId)/user"
                Body = @{   
                    userId = $userResponse[0].primaryEmail
                }
                Method = 'POST' 
                Headers = $authorization
            }
            $response = Invoke-RestMethod @splat
            $success = $True
            $auditMessage += " successfully"
        }
        else
        {
            $success = $False
            $auditMessage += " not successfully (unknown permission type: {0})" -f $pRef.Type
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
            $success = $false;
            $auditMessage = " : General error $($_)";
        }
    }
}

#build up result
$result = [PSCustomObject]@{
    Success = $success
    AuditDetails = $auditMessage
    Account = $account
}

Write-Output ($result | ConvertTo-Json -Depth 10)