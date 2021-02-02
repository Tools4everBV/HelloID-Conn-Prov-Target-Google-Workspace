#2021-01-25 - Update Google Account
$config = ConvertFrom-Json $configuration
 
#Initialize default properties
$p = $person | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$success = $False
$auditMessage = ""

$defaultDomain = $config.defaultDomain
$max_namegen_iterations = 10
$default_ou = "/Student Accounts/Active"

# Get Mail from Active Directory target system
$ad_mail = $p.Accounts.MicrosoftActiveDirectory.mail

#Target OrgUnitPath
$calc_ou = ("{0}/{1}/{2}" -f
    $default_ou,
    $p.PrimaryContract.Department.ExternalID,
    $p.custom.GradYear
    )
Write-Information ("Target OU: {0}" -f $calc_ou )

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
Write-Information ("Initial Primary_Email: {0}" -f $calc_primary_email)

#Define mapping here
#For all of the supported attributes please check https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
$account = [PSCustomObject]@{
    primaryEmail = 'TBD' # Set after making sure the Calc PrimaryEmail is available.
    name = @{
                givenName = "$($p.Name.NickName)"
                familyName = "$($p.Name.FamilyName)"
                fullName = "$($p.Name.NickName) $($p.Name.FamilyName)"
            }
    externalIds = @(@{
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
    orgUnitPath = "TBD"
}

try{
    #Add the authorization header to the request
    $authorization = google-refresh-accessToken

    # Verify Target OU Exists.  Else, use Default OU
    $splat = @{
        Uri = ("https://www.googleapis.com/admin/directory/v1/customer/my_customer/orgunits{0}" -f $calc_ou)
        Method = 'GET'
        Headers = $authorization
        Verbose = $False
    }
    #  API will error if target OU does not exist.
    try {
        $response = Invoke-RestMethod @splat
        $account.orgUnitPath = $calc_ou
    }
    catch {
        Write-Information ("Target OU Not found.  Using Default OU: {0}" -f $default_ou)
        $account.orgUnitPath = $default_ou
    }

    # Verify Primary Email Address
    $Iterator = 0
    do {
        #Get Target Primary Email
        #  If Exists, check result to see if has matching ID.  If not, iterate.
        $splat = @{
            Body = @{
                customer = "my_customer"
                query = "Email=$($calc_primary_email)"
                projection="FULL"
            }
            Uri = "https://www.googleapis.com/admin/directory/v1/users" 
            Method = 'GET'
            Headers = $authorization
            Verbose =$False
        }
        $primaryEmailResponse = Invoke-RestMethod @splat

        # Count = 0 - Email not taken.  Use it.
        # Count > 0 - Email taken
        #     Check ID:  If match, use it.  If not, iterate.
        if($primaryEmailResponse.users.count -eq 0 -OR $primaryEmailResponse.users[0].id -eq $aRef)
        {
            #Use it
            $account.primaryEmail = $calc_primary_email
        } else
        {
            #Iterate
            Write-Information "$($account.primaryEmail) already in use, iterating)"
            $Iterator++
            $calc_primary_email = generate-PrimaryEmail -firstName $p.Name.NickName -lastName $p.Name.FamilyName -domain $defaultDomain -Iteration $Iterator
            $account.primaryEmail = $calc_primary_email
        }
    } while ($account.primaryEmail -eq 'TBD' -AND $Iterator -lt $max_namegen_iterations)
    
    #Check for exceeding max namegen iterations
    if($Iterator -ge $max_namegen_iterations)
    {
        throw "Max NameGen Iterations tested.  No unique Primary Email values found.  Iterated values may not be allowed in NameGen algorithm."
    }
    Write-Information ("Using Primary Email: {0}" -f $calc_primary_email)

    # Update Account
    if(-Not $dryRun){
        # Get Previous Account
        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" 
            Method = 'GET'
            Headers = $authorization 
            Verbose = $False
        }
        $previousAccount = Invoke-RestMethod @splat

        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" 
            Method = 'PUT'
            Headers = $authorization 
            Body = ($account | ConvertTo-Json -Depth 10)
            Verbose = $False
        }
        $updated_account = Invoke-RestMethod @splat
    }
    $success = $True
    $auditMessage = "Updated account with PrimaryEmail $($updated_account.primaryEmail) in OrgUnit [$($account.orgUnitPath)]"
}catch{
    $auditMessage = "Error updating account with PrimaryEmail $($account.primaryEmail) - Error: $($_)"
    Write-Error $_
}
 
#build up result
$result = [PSCustomObject]@{
    Success = $success
    AccountReference = $aRef
    AuditDetails = $auditMessage
    Account = $updated_account
    PreviousAccount = $previousAccount
    
    ExportData = [PSCustomObject]@{
        primaryEmail = $updated_account.primaryEmail
        orgUnitPath = $updated_account.orgUnitPath
    }
};
  
Write-Output ($result | ConvertTo-Json -Depth 10)
