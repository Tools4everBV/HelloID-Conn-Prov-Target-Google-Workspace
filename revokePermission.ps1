#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
$pRef = $permissionReference | ConvertFrom-json

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

#region Execute
if(-Not($dryRun -eq $True)) {
    try
    {
        #Add the authorization header to the request
        $authorization = Get-GoogleAccessToken
        
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

            $auditLogs.Add([PSCustomObject]@{
                Action = "RevokeMembership"
                Message = "Membership for person $($p.DisplayName) removed from $($pRef.Displayname) successfully"
                IsError = $false;
            });
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
            
            $auditLogs.Add([PSCustomObject]@{
                Action = "RevokeMembership"
                Message = "Membership for person $($p.DisplayName) removed from $($pRef.Displayname) successfully"
                IsError = $false;
            });
        }
        else
        {
            $success = $False
            
            $auditLogs.Add([PSCustomObject]@{
                Action = "RevokeMembership"
                Message = "Membership for person $($p.DisplayName) to $($pRef.DisplayName) not successful (unknown permission type: $($pRef.Type))"
                IsError = $true;
            });
        }
    }catch
    {
        if($_.Exception.Response.StatusCode.value__ -eq 412)
        {
            $success = $True
            
            $auditLogs.Add([PSCustomObject]@{
                Action = "RevokeMembership"
                Message = "Membership for person $($p.DisplayName) removed from $($pRef.Displayname) successfully (Auto License un-assignment is not allowed.)"
                IsError = $false;
            });
        }
        else
        {
            $auditLogs.Add([PSCustomObject]@{
                Action = "RevokeMembership"
                Message = "Membership for person $($p.DisplayName) removed from $($pRef.DisplayName) not successful - $($_)"
                IsError = $true
            });
            
            Write-Error $_;
        }
    }
}
#endregion Execute

#region Build up result
$result = [PSCustomObject]@{
    Success = $success
    AuditDetails = $auditMessage
}
 
Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion Build up result