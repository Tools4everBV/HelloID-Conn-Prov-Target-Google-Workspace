#2021-01-25 - Google Revoke Permission
$config = ConvertFrom-Json $configuration

#Initialize default properties
$p = $person | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-json

$success = $False
$auditMessage = "Membership for person $($p.DisplayName) removed from $($pRef.Displayname)"

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
    }
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
        Write-Information "Primary Email: $($userResponse[0].primaryEmail)"
        
        if($pRef.Type -eq "Group")
        {
            Write-Information "Revoking Group Permission"
            $splat = @{
                Uri = "https://www.googleapis.com/admin/directory/v1/groups/$($pRef.Id)/members/$($userResponse[0].primaryEmail)"
                Method = 'DELETE'
                Headers = $authorization
            }
            $response = Invoke-RestMethod @splat
            $success = $True
            $auditMessage += " successfully"
        }
        elseif($pRef.Type -eq "License")
        {
            Write-Information "Revoking License Permission"
            $splat = @{
                Uri = "https://www.googleapis.com/apps/licensing/v1/product/$($pRef.ProductId)/sku/$($pRef.SkuId)/user/$($userResponse[0].primaryEmail)" 
                Method = 'DELETE' 
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
        if($_.Exception.Response.StatusCode.value__ -eq 412)
        {
            $success = $True
            $auditMessage += " successfully (Auto License un-assignment is not allowed.)"
        }
        else
        {
            $auditMessage += " : General error $($_)"
            Write-Error -Verbose $_
        }
    }
}

#build up result
$result = [PSCustomObject]@{
    Success = $success
    AuditDetails = $auditMessage
}
 
Write-Output ($result | ConvertTo-Json -Depth 10)
