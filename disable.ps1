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

    # Add the authorization header to the request
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
	try {
		$response = Invoke-RestMethod @splat
		Write-Information ("Get-GoogleOuExists: Target OU {0} exists." -f $orgUnitPath)
		
		$googleOuExists = $true
	} catch {
		if ($createOuIfNotExists -eq $true) {
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
		} else {
			Write-Information ("Get-GoogleOuExists: Target OU {0} does not exist." -f $orgUnitPath)
		}
	}
	
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
        suspended = $True
        orgUnitPath = $calcOrgUnitPath
        # includeInGlobalAddressList = $false
    }
#endregion Change mapping here

#region Execute
try{
    #Add the authorization header to the request
    $authorization = Get-GoogleAccessToken

    # Verify Target OU Exists.  Else, use Default OU
    $targetOuExists = Get-GoogleOuExists -orgUnitPath $calcOrgUnitPath -createOuIfNotExists $false -authorization $authorization 

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
        $previousAccount = Invoke-RestMethod @splat

        $splat = @{
            body = [System.Text.Encoding]::UTF8.GetBytes(($account | ConvertTo-Json -Depth 10))
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)"
            Method = 'PUT'
            Headers = $authorization
            Verbose = $False
        }
        $updatedAccount = Invoke-RestMethod @splat
        #Write-Information ("Response: {0}" -f ($response | ConvertTo-Json -Depth 50))

        $auditLogs.Add([PSCustomObject]@{
            Action = "DisableAccount"
            Message = "Disabled/Updated account with PrimaryEmail $($updatedAccount.primaryEmail) in OrgUnit [$($updatedAccount.orgUnitPath)]"
            IsError = $false;
        });
    }
    else {
        $updatedAccount = $account;
    }

    $success = $True
}catch{
    if($_.Exception.Response.StatusCode.value__ -eq 404)
    {
        $success = $True
        $auditLogs.Add([PSCustomObject]@{
            Action = "DisableAccount"
            Message = "Disable Skipped, Account doesn't exist [$($aRef)]"
            IsError = $false;
        });

    }
    else
    {
        $auditLogs.Add([PSCustomObject]@{
            Action = "DisableAccount"
            Message = "Error disabling/updating account with PrimaryEmail $($previousAccount.primaryEmail) - Error: $($_)"
            IsError = $true;
        });
        Write-Error $_
    }
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