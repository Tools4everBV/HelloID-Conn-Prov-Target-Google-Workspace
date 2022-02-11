#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json;


$success = $False
$auditLogs = [Collections.Generic.List[PSCustomObject]]@()
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

function Get-GoogleOuExists {
    param (
        [Parameter(Mandatory)]
        [string]$orgUnitPath,
        [bool]$createOuIfNotExists = $false,
        [Parameter(Mandatory)]
        $authorization
    )
    $googleOuExists = $false
    
    $splat = @{
        Uri = ("https://www.googleapis.com/admin/directory/v1/customer/my_customer/orgunits{0}" -f $orgUnitPath)
        Method = 'GET'
        Headers = $authorization
        Verbose = $False
        ErrorAction = 'Stop'
    }
    #  API will error if target OU does not exist.
    $retryCount = 0
    do{
        $retry = $false
        try {
            $response = Invoke-RestMethod @splat
            Write-Information ("Get-GoogleOuExists: Target OU {0} exists." -f $orgUnitPath)
            
            $googleOuExists = $true
        } catch {
            if ($_.ErrorDetails.Message -match "Org unit not found" -AND $createOuIfNotExists -eq $true) {
                # Create the target OU
                try {
                    $leafOU = $orgUnitPath.split("/")[-1]
                    $parentOU = $orgUnitPath.replace("/$leafOu","")
                    
                    $splat = @{
                        Uri = "https://www.googleapis.com/admin/directory/v1/customer/my_customer/orgunits"
                        Method = 'POST'
                        Headers = $authorization
                        Verbose = $true
                        ErrorAction = 'Stop'
                        Body = "{
                            'name':'$leafOU',
                            'parentOrgUnitPath': '$parentOU'
                            }"
                    }
                    $response = Invoke-RestMethod @splat

                    Write-Information ("Get-GoogleOuExists: Created organizational unit {0}." -f $orgUnitPath)
                    $googleOuExists = $true
                } catch {
                    Write-Information ("Get-GoogleOuExists: Failed to create organizational unit {0}. Verify parent path exists." -f $orgUnitPath)
                    Write-Error $_
                }
            }
            elseif ($_.ErrorDetails.Message -match "Org unit not found" -OR $retryCount -ge 5)
            {
                Write-Information ("Get-GoogleOuExists: Target OU {0} does not exist." -f $orgUnitPath)
            }
            elseif ($_.ErrorDetails.Message -match "Quota exceeded")
            {
                $retry = $true
                Start-Sleep -Milliseconds (([Math]::Pow(2,$retryCount++) * 1000) + (Get-Random 1000))
            }
            else # Unknown Error
            {
                Write-Information ("Get-GoogleOuExists: Unknown Error Finding OU.  Using Default OU: {0}" -f $defaultOrgUnitPath)
            }
        }
    } while ($retry)
    
    return $googleOuExists
}
#endregion Support Functions

#region Change mapping here
    $defaultOrgUnitPath = "/Employees"

    #Target OrgUnitPath
    $calcOrgUnitPath = ("{0}/{1}" -f
        $defaultOrgUnitPath,
        $p.PrimaryContract.Department.ExternalID
        )
    Write-Information ("Target OU: {0}" -f $calcOrgUnitPath)

    #Change mapping here
    $account = @{
        suspended = $False
        orgUnitPath = $calcOrgUnitPath;
    }
#endregion Change mapping here

#region Execute
try{
    #Add the authorization header to the request
    $authorization = Get-GoogleAccessToken

    # Verify Target OU Exists.  Else, use Default OU
    $targetOuExists = Get-GoogleOuExists -orgUnitPath $calcOrgUnitPath -createOuIfNotExists $config.createOuIfNotExists -authorization $authorization 

    if ($targetOuExists -eq $true) {
        $account.orgUnitPath = $calcOrgUnitPath
    } else {
        Write-Information ("Target OU Not found.  Using Default OU: {0}" -f $defaultOrgUnitPath)
        $account.orgUnitPath = $defaultOrgUnitPath
    }

    #Send User Update
    if(-Not($dryRun -eq $True)) {
        # Get Previous Account
        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)"
            Method = 'GET'
            Headers = $authorization
            Verbose = $False
        }
        $retryCount = 0
        do{
            $retry = $false
            try {
                $previousAccount = Invoke-RestMethod @splat
            }
            catch {
                if ($_.ErrorDetails.Message -match "Quota exceeded" -AND $retryCount -lt 5)
                {
                    $retry = $true
                    Start-Sleep -Milliseconds (([Math]::Pow(2,$retryCount++) * 1000) + (Get-Random 1000))
                }
                else
                {
                    write-error ("Unknown Error: {0}" -f $_)
                    throw $_
                }
            }
        } while ($retry)

        $splat = @{
            body = [System.Text.Encoding]::UTF8.GetBytes(($account | ConvertTo-Json -Depth 10))
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)"
            Method = 'PUT'
            Headers = $authorization
            Verbose = $False
        }
        $retryCount = 0
        do{
            $retry = $false
            try {
                $updatedAccount = Invoke-RestMethod @splat
                #Write-Information ("Response: {0}" -f ($response | ConvertTo-Json -Depth 50))
            }
            catch {
                if ($_.ErrorDetails.Message -match "Quota exceeded" -AND $retryCount -lt 5)
                {
                    $retry = $true
                    Start-Sleep -Milliseconds (([Math]::Pow(2,$retryCount++) * 1000) + (Get-Random 1000))
                }
                else
                {
                    write-error ("Unknown Error: {0}" -f $_)
                    throw $_
                }
            }
        } while ($retry)
        
        $auditLogs.Add([PSCustomObject]@{
            Action = "EnableAccount"
            Message = "Enabled/Updated account with PrimaryEmail $($updatedAccount.primaryEmail) in OrgUnit [$($updatedAccount.orgUnitPath)]"
            IsError = $false;
        });
    }
    else {
        $updatedAccount = $account;
    }

    $success = $True
}catch{
    $auditLogs.Add([PSCustomObject]@{
        Action = "EnableAccount"
        Message = "Error enabling/updating account with PrimaryEmail $($previousAccount.primaryEmail) - Error: $($_)"
        IsError = $true;
    });
    Write-Error $_
}
#endregion Execute

#region Build up result
$result = [PSCustomObject]@{
    Success = $success
    AccountReference = $aRef
    AuditLogs = $auditLogs;
    Account = $updatedAccount
    PreviousAccount = $previousAccount

    ExportData = [PSCustomObject]@{
        OrgUnitPath = $updatedAccount.orgUnitPath
    }
}

Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion Build up result