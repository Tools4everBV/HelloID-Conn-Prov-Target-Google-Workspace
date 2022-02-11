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

#Primary Email Generation
# 1. <First Name>.<Last Name>@<Domain> (e.g john.williams@yourdomain.com)
# 2. <First Name>.<Last Name><Iterator>@<Domain> (e.g john.williams2@yourdomain.com)
function New-PrimaryEmail {
    [cmdletbinding()]
    Param (
        [object]$person,
        [string]$domain,
        [int]$Iteration
    )
    Process {
        $suffix = "";
        if($Iteration -gt 0) { $suffix = "$($Iteration+1)" };

        #Check Nickname
        if([string]::IsNullOrEmpty($p.Name.Nickname)) { $tempFirstName = $p.Name.GivenName } else { $tempFirstName = $p.Name.Nickname }

        $tempLastName = $person.Name.FamilyName;
        $tempUsername = ("{0}.{1}" -f $tempFirstName,$tempLastName);
        $tempUsername = $tempUsername.substring(0,[Math]::Min(20-$suffix.Length,$tempUsername.Length));
        $result = ("{0}{1}@{2}" -f $tempUsername, $suffix, $domain);
        $result = $result.toLower();

        return $result;
    }
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
    $defaultDomain = $config.defaultDomain
    $defaultOrgUnitPath = "/Employees"
    $enableUpdatePrimaryEmail = $false;

    #Target OrgUnitPath
    $calcOrgUnitPath = ("{0}/{1}" -f
        $defaultOrgUnitPath,
        $p.PrimaryContract.Department.ExternalID
        )
    Write-Information ("Target OU: {0}" -f $calcOrgUnitPath )

    #Username Generation
    $maxUsernameIterations = 10
    $calcPrimaryEmail = New-PrimaryEmail -person $p -domain $defaultDomain -Iteration 0
    Write-Information "Initial Generated Email: $($calcPrimaryEmail)"

    #Determine First Name (NickName vs GivenName)
    if([string]::IsNullOrEmpty($p.Name.Nickname)) { $calcFirstName = $p.Name.GivenName } else { $calcFirstName = $p.Name.Nickname }

    #Define mapping here
    #For all of the supported attributes please check https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
    $account = [PSCustomObject]@{
        primaryEmail = "TBD" # Set after making sure the calcPrimaryEmail is available.
        name = @{
            givenName = "$($calcFirstName)"
            familyName = "$($p.Name.FamilyName)"
            fullName = "$($calcFirstName) $($p.Name.FamilyName)"
        }
        organizations = @(@{
            title = "$($p.primaryContract.Title.name)"
            department = "$($p.primaryContract.Department.name)"
        })
        orgUnitPath = $calcOrgUnitPath # Set after making sure calcOrgUnitPath exists, else defaultOU
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

    #Check if Username Change Enabled
    if($enableUpdatePrimaryEmail) {
        # Verify Primary Email Address
        $Iterator = 0
        do {
            #Get Target Primary Email
            #  If Exists, check result to see if has matching ID.  If not, iterate.
            $splat = @{
                Body = @{
                    customer = "my_customer"
                    query = "Email=$($calcPrimaryEmail)"
                    projection="FULL"
                }
                Uri = "https://www.googleapis.com/admin/directory/v1/users"
                Method = 'GET'
                Headers = $authorization
                Verbose = $False
            }
            $retryCount = 0
            do{
                $retry = $false
                try {
                    $primaryEmailResponse = Invoke-RestMethod @splat
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
            
            # Count = 0 - Email not taken.  Use it.
            # Count > 0 - Email taken
            #     Check ID:  If match, use it.  If not, iterate.
            if($primaryEmailResponse.users.count -eq 0 -OR $primaryEmailResponse.users[0].id -eq $aRef)
            {
                #Use it
                $account.primaryEmail = $calcPrimaryEmail
            } else
            {
                #Iterate
                Write-Information "$($account.primaryEmail) already in use, iterating)"
                $Iterator++
                $calcPrimaryEmail = New-PrimaryEmail -person $p -domain $defaultDomain -Iteration $Iterator
                $account.primaryEmail = $calcPrimaryEmail
                Write-Information "Iteration $($Iterator) - $($account.primaryEmail)"
            }
        } while ($account.primaryEmail -eq 'TBD' -AND $Iterator -lt $maxUsernameIterations)

        #Check for exceeding max namegen iterations
        if($Iterator -ge $maxUsernameIterations)
        {
            throw "Max NameGen Iterations tested.  No unique Primary Email values found.  Iterated values may not be allowed in NameGen algorithm."
        }
        Write-Information ("Using Primary Email: {0}" -f $calcPrimaryEmail)
    }
    else {
        $account.PSObject.Properties.Remove("primaryEmail");
        Write-Information ("Keep existing Primary Email");
    }
    # Update Account
    if(-Not($dryRun -eq $True)){
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
        
        # Send Updated Account Settings
        $splat = @{
            Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)"
            Method = 'PUT'
            Headers = $authorization
            Body = [System.Text.Encoding]::UTF8.GetBytes(($account | ConvertTo-Json -Depth 10))
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

        #Write-Information ("Updated Account: {0}" -f ($updatedAccount | ConvertTo-Json -Depth 10))
        $auditLogs.Add([PSCustomObject]@{
            Action = "UpdateAccount"
            Message = "Updated account with PrimaryEmail $($updatedAccount.primaryEmail) in OrgUnit [$($account.orgUnitPath)]"
            IsError = $false;
        });
    }
    else {
        $updatedAccount = $account;
    }
    $success = $True

} catch {
    $auditLogs.Add([PSCustomObject]@{
        Action = "UpdateAccount"
        Message = "Error updating account with PrimaryEmail $($account.primaryEmail) - Error: $($_)"
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
        PrimaryEmail = $updatedAccount.primaryEmail
        OrgUnitPath = $updatedAccount.orgUnitPath
    }
};

Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion Build up result