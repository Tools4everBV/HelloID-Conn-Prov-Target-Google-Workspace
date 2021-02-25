#2021-02-02 - Create Google Account
$config = ConvertFrom-Json $configuration
 
#Initialize default properties
$p = $person | ConvertFrom-Json
$success = $False
$auditMessage = ""

# Get Mail from Active Directory target system
$ad_mail = $p.Accounts.MicrosoftActiveDirectory.mail

#Defaults, create only
#$defaultPassword = [System.Web.Security.Membership]::GeneratePassword(10, 0) ##Method doesn't work with cloud agent. See https://github.com/Tools4everBV/HelloID-Conn-Prov-HelperFunctions/blob/master/PowerShell/Algorithms/password.random.cloudagent.ps1
$defaultPassword = ("00{0}" -f $p.ExternalId)
$passwordHash = ([System.BitConverter]::ToString((New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider).ComputeHash((New-Object -TypeName System.Text.UTF8Encoding).GetBytes($defaultPassword)))).Replace("-","")
$usePasswordHash = $true
$defaultDomain = $config.defaultDomain
$defaultOrgUnitPath = "/Student Accounts/Inactive"
$defaultSuspended = $true
$max_namegen_iterations = 10

# Support Functions
function google-refresh-accessToken()
{
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

#Primary Email Generation
# 1. <First Name>.<Last Name>@<Domain> (e.g john.williams@yourdomain.com)
# 2. <First Name>.<Last Name><Iterator>@<Domain> (e.g john.williams2@yourdomain.com)
function generate-PrimaryEmail {
	[cmdletbinding()]
	Param (
		[string]$firstName,
		[string]$lastName,
		[string]$domain,
		[int]$Iteration
	) 
	Process 
    {
		<#
		$suffix = ""
        if($Iteration -gt 0) { $suffix = "$($Iteration+1)" }
        
        $temp_fn = $firstName
        $temp_ln = $lastName
        $temp_username = $temp_fn + "." + $temp_ln
        $temp_username = $temp_username.substring(0,[Math]::Min(20-$suffix.Length,$t.Length))
        
        $result = $temp_username + $suffix + $domain
        $result = $result.toLower()
        @($result)
		#>
		return $ad_mail
    }
}

$calc_primary_email = generate-PrimaryEmail -firstName $p.Name.NickName -lastName $p.Name.FamilyName -domain $defaultDomain -Iteration 0
Write-Information ("Initial Generated Email: {0}" -f $calc_primary_email)

#Change mapping here
#For all of the supported attributes please check https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
$account = [ordered]@{
    primaryEmail = $calc_primary_email
    name = @{
                givenName = "$($p.Name.NickName)"
                familyName = "$($p.Name.FamilyName)"
                fullName = "$($p.Name.NickName) $($p.Name.FamilyName)"
            }
    externalIds =  @(@{
                        value = "$($p.ExternalId)"
                        type = "custom"
                        customType = "$($p.Custom.Role)"
                    })
    organizations = @(@{
                        #title = "$($p.primaryContract.Title.name)"
                        title = "$($p.Custom.Role)"
                        department = "$($p.primaryContract.Department.ExternalId)"
                        #costCenter = "$($p.primaryContract.costCenter.ExternalID)"
                    })
}
Write-Information ("Initial Account: {0}" -f ($account | ConvertTo-Json -Depth 20))

try
{
    #Add the authorization header to the request
    $authorization = google-refresh-accessToken

    #Check if account exists (based on externalId), else create
    $splat = @{
        Body = @{
            customer = "my_customer"
            query = "externalId=$($p.ExternalId)"
            projection="FULL"
        }
        Uri = "https://www.googleapis.com/admin/directory/v1/users"
        Method = 'GET'
        Headers = $authorization
        Verbose = $False
    }
    $correlationResponse = Invoke-RestMethod @splat
    
    if($correlationResponse.users.count -gt 0)
    {
        Write-Information ("Existing Account found: (Found count: {0}) {1}" -f $correlationResponse.users.count,($correlationResponse.users | ConvertTo-Json -Depth 20))
        
        $aRef = $correlationResponse.users[0].id
        
        #Use existing primaryEmail and OrgUnitPath
        $calc_primary_email = $correlationResponse.users[0].primaryEmail
		$account.primaryEmail = $calc_primary_email
        $account.orgUnitPath = $correlationResponse.users[0].orgUnitPath

        # Update Existing User
        if(-Not($dryRun -eq $True)){
            $previousAccount = $correlationResponse.users[0]

            $splat = [ordered]@{
                body = ($account | ConvertTo-Json -Depth 10)
                Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" 
                Method = 'PUT'
                Headers = $authorization 
                Verbose = $False
            }
            $newAccount = Invoke-RestMethod @splat
            $auditMessage = "Found and linked account with PrimaryEmail $($newAccount.primaryEmail)";
            Write-Information ("Updated Existing Account: {0}" -f ($newAccount | ConvertTo-Json -Depth 10))
        }
    }
    else
    {
        # Verify Primary Email Uniqueness (NOTE: only checks against other Google accounts)
        $Iterator = 0
        do {
            #Check if username taken
            $splat = [ordered]@{
                Body = @{
                    customer = "my_customer"
                    query = "Email=$($account.primaryEmail)"
                    projection="FULL"
                }
                Uri = "https://www.googleapis.com/admin/directory/v1/users" 
                Method = 'GET'
                Headers = $authorization
                Verbose =$False
            }
            $calc_primary_emailResponse = Invoke-RestMethod @splat

            if($calc_primary_emailResponse.users.count -gt 0)
            {
                #Iterate
                Write-Verbose -Verbose "$($account.primaryEmail) already in use, iterating)"
                $Iterator++
				$calc_primary_email = generate-PrimaryEmail -firstName $p.Name.NickName -lastName $p.Name.FamilyName -domain $defaultDomain -Iteration $Iterator
                $account.primaryEmail = $calc_primary_email
            }
        } while ($calc_primary_emailResponse.users.count -gt 0 -AND $Iterator -lt $max_namegen_iterations)
        
		#Check for exceeding max namegen iterations
		if($Iterator -ge $max_namegen_iterations)
		{
			throw "Max NameGen Iterations tested.  No unique Primary Email values found.  Iterated values may not be allowed in NameGen algorithm."
		}
		
        #Proceed with account creation, set additional defaults 
        if($usePasswordHash -eq $true)
		{
			$account.password = $passwordHash
			$account.hashFunction = "SHA-1"
		}
		else
		{
			$account.password = $defaultPassword
		}
        $account.orgUnitPath = $defaultOrgUnitPath
        $account.suspended = $defaultSuspended
        
        if(-Not($dryRun -eq $True)){
            $splat = [ordered]@{
                Body = $account | ConvertTo-Json -Depth 10
                Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" 
                Method = 'POST'
                Headers = $authorization 
                Verbose = $False
            }
            $newAccount = Invoke-RestMethod @splat
            $aRef = $newAccount.id
            Write-Information ("New Account Created:  {0}" -f ($newAccount | ConvertTo-Json -Depth 10))
            # Add Password for use in Onboard Notification
            $newAccount | Add-Member -NotePropertyName password -NotePropertyValue $defaultPassword
            $auditMessage = "Created account with PrimaryEmail $($newAccount.primaryEmail)"
        }
    }
    $success = $True
}catch{
    $auditMessage = "Error creating account with PrimaryEmail $($account.primaryEmail) - Error: $($_)"
    Write-Error $_
}

#build up result
$result = [PSCustomObject]@{
	Success = $success
	AccountReference = $aRef
	AuditDetails = $auditMessage
	Account = $newAccount
	PreviousAccount = $previousAccount
	
	# Optionally return data for use in other systems
    ExportData = [PSCustomObject]@{
        PrimaryEmail = $newAccount.PrimaryEmail
        OrgUnitPath = $newAccount.orgUnitPath
    }
}
  
Write-Output ($result | ConvertTo-Json -Depth 10)
