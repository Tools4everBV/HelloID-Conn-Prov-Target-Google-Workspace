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
        'Content-Type' = "application/json; charset=utf-8";
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
        Write-Information "Found user: $($userResponse[0].primaryEmail)"

        if($pRef.Type -eq "Group")
        {
            Write-Information "Applying Group Permission"

            $account = [PSCustomObject]@{
                    email = $userResponse[0].primaryEmail
                    role = "MEMBER"
                }

            $splat = @{
                Uri = "https://www.googleapis.com/admin/directory/v1/groups/$($pRef.Id)/members"
                Body = [System.Text.Encoding]::UTF8.GetBytes(($account | ConvertTo-Json))
                Method = 'POST'
                Headers = $authorization
            }

            $response = Invoke-RestMethod @splat
            $success = $True

            $auditLogs.Add([PSCustomObject]@{
                Action = "GrantMembership"
                Message = "Membership for person $($p.DisplayName) added to $($pRef.DisplayName) successfully"
                IsError = $false;
            });
        }
        elseif($pRef.Type -eq "License")
        {
            Write-Information "Applying License Permission"

            $account = [PSCustomObject]@{
                    userId = $userResponse[0].primaryEmail
                }

            $splat = @{
                Uri = "https://licensing.googleapis.com/apps/licensing/v1/product/$($pRef.ProductId)/sku/$($pRef.SkuId)/user"
                Body = [System.Text.Encoding]::UTF8.GetBytes(($account | ConvertTo-Json))
                Method = 'POST'
                Headers = $authorization
            }
            $response = Invoke-RestMethod @splat
            $success = $True

            $auditLogs.Add([PSCustomObject]@{
                Action = "GrantMembership"
                Message = "Membership for person $($p.DisplayName) added to $($pRef.DisplayName) successfully"
                IsError = $false;
            });
        }
        else
        {
            $success = $False
            Write-Error "(unknown permission type: $($pRef.Type))";
            $auditLogs.Add([PSCustomObject]@{
                Action = "GrantMembership"
                Message = "Membership for person $($p.DisplayName) to $($pRef.DisplayName) not successful (unknown permission type: $($pRef.Type))"
                IsError = $true;
            });
        }
    }catch
    {
        Write-Information "Status Code: $($_.Exception.Response.StatusCode.value__)"
        Write-Information ($_ | ConvertFrom-Json).error.message;
        if($_.Exception.Response.StatusCode.value__ -eq 409)
        {
            $success = $True;

            $auditLogs.Add([PSCustomObject]@{
                Action = "GrantMembership"
                Message = "Membership for person $($p.DisplayName) added to $($pRef.DisplayName) (already exists)"
                IsError = $false
            });
        }
        elseif($_.Exception.Response.StatusCode.value__ -eq 412)
        {
            if( ($_ | ConvertFrom-Json).error.message -like "*User already has a license for the specified product and SKU*" )
            {
                $success = $true;

                $auditLogs.Add([PSCustomObject]@{
                    Action = "GrantMembership"
                    Message = "Membership for person $($p.DisplayName) added to $($pRef.DisplayName) (already exists)"
                    IsError = $false
                });
            }
            else
            {
                $success = $false;
                $auditLogs.Add([PSCustomObject]@{
                    Action = "GrantMembership"
                    Message = "Membership for person $($p.DisplayName) added to $($pRef.DisplayName) not successful - $($_)"
                    IsError = $true
                });

                Write-Error $_;
            }
        }
        else
        {
            $success = $false;
            $auditLogs.Add([PSCustomObject]@{
                Action = "GrantMembership"
                Message = "Membership for person $($p.DisplayName) added to $($pRef.DisplayName) not successful - $($_)"
                IsError = $true
            });

            Write-Error $_;
        }
    }
}
#endregion Execute

#region Build up result
Write-Information ($auditLogs | ConvertTo-Json)
$result = [PSCustomObject]@{
    Success = $success
    Account = $account
    AuditLogs = $auditLogs;
}

Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion Build up result