#region Initialize default properties
$config = ConvertFrom-Json $configuration
$p = $person | ConvertFrom-Json
$pp = $previousPerson | ConvertFrom-Json
$pd = $personDifferences | ConvertFrom-Json
$m = $manager | ConvertFrom-Json

$success = $False
$auditLogs = New-Object Collections.Generic.List[PSCustomObject];
#endregion Initialize default properties

#region Support Functions
function New-RandomPassword($PasswordLength) {
    if($PasswordLength -lt 8) { $PasswordLength = 8}
        
    # Used to store an array of characters that can be used for the password
    $CharPool = New-Object System.Collections.ArrayList

    # Add characters a-z to the arraylist
    for ($index = 97; $index -le 122; $index++) { [Void]$CharPool.Add([char]$index) }

    # Add characters A-Z to the arraylist
    for ($index = 65; $index -le 90; $index++) { [Void]$CharPool.Add([Char]$index) }

    # Add digits 0-9 to the arraylist
    $CharPool.AddRange(@("0","1","2","3","4","5","6","7","8","9"))
        
    # Add a range of special characters to the arraylist
    $CharPool.AddRange(@("!","""","#","$","%","&","'","(",")","*","+","-",".","/",":",";","<","=",">","?","@","[","\","]","^","_","{","|","}","~","!"))
        
    $password=""
    $rand=New-Object System.Random
        
    # Generate password by appending a random value from the array list until desired length of password is reached
    1..$PasswordLength | foreach { $password = $password + $CharPool[$rand.Next(0,$CharPool.Count)] }  
        
    $password
}

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
        Authorization = "Bearer $($accesstoken)";
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
    Process 
    {
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

function Get-CorrelationResult {
    [cmdletbinding()]
    Param (
        [object]$authorization,
        [string]$field,
        [string]$value
    ) 
    Process 
    {
        $splat = @{
            Body = @{
                customer = "my_customer"
                query = "$($field)=$($value)"
                projection="FULL"
            }
            Uri = "https://www.googleapis.com/admin/directory/v1/users"
            Method = 'GET'
            Headers = $authorization
            Verbose = $False
        }
        $correlationResponse = Invoke-RestMethod @splat
        return $correlationResponse
    }
}
#endregion Support Functions

#region Change mapping here
    #Defaults, create only
    $usePasswordHash = $true
    $defaultPassword = New-RandomPassword(8)
    $passwordHash = ([System.BitConverter]::ToString((New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider).ComputeHash((New-Object -TypeName System.Text.UTF8Encoding).GetBytes($defaultPassword)))).Replace("-","")

    $defaultDomain = $config.defaultDomain
    $defaultOrgUnitPath = "/Disabled"
    $defaultSuspended = $true

    #Correlation
    $useCorrelation = $config.correlationEnabled;
    $correlationPersonField = ($config.correlationPersonField | Invoke-Expression)
    $correlationAccountField = $config.correlationAccountField

    #Username Generation
    $maxUsernameIterations = 10
    $calcPrimaryEmail = New-PrimaryEmail -person $p -domain $defaultDomain -Iteration 0
    Write-Information "Initial Generated Email: $($calcPrimaryEmail)"

    #Determine First Name (NickName vs GivenName)
    if([string]::IsNullOrEmpty($p.Name.Nickname)) { $calcFirstName = $p.Name.GivenName } else { $calcFirstName = $p.Name.Nickname }

    #For all of the supported attributes please check https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
    $account = [ordered]@{
        primaryEmail = $calcPrimaryEmail
        name = @{
                    givenName = "$($calcFirstName)"
                    familyName = "$($p.Name.FamilyName)"
                    fullName = "$($calcFirstName) $($p.Name.FamilyName)"
                }
        externalIds =  @(@{
                            value = "$($p.ExternalId)"
                            type = "organization" # EmployeeID
                        })
        organizations = @(@{
                            title = "$($p.primaryContract.Title.name)"
                            department = "$($p.primaryContract.Department.name)"
                        })
    }
    
    #Write-Information ("Initial Account: {0}" -f ($account | ConvertTo-Json -Depth 20))
#endregion Change mapping here

#region Execute
try
{
    #Add the authorization header to the request
    $authorization = Get-GoogleAccessToken

    if($useCorrelation)
    {
        #Check if account exists (based on externalId), else create
        $splat = @{
            authorization = $authorization
            field = $correlationAccountField
            value = $correlationPersonField
        }
        $correlationResponse = Get-CorrelationResult @splat
    }
    if($correlationResponse.users.count -gt 0)
    {
        Write-Information ("Existing Account found: (Found count: {0}) {1}" -f $correlationResponse.users.count,($correlationResponse.users | ConvertTo-Json -Depth 20))
        
        $aRef = $correlationResponse.users[0].id
        
        #Use existing primaryEmail and OrgUnitPath
        $calcPrimaryEmail = $correlationResponse.users[0].primaryEmail
        $account.primaryEmail = $calcPrimaryEmail
        $account.orgUnitPath = $correlationResponse.users[0].orgUnitPath

        # Update Existing User
        if(-Not($dryRun -eq $True)){
            $previousAccount = $correlationResponse.users[0]

            $auditLogs.Add([PSCustomObject]@{
                Action = "CreateAccount"
                Message = "Found and correlated account with PrimaryEmail $($previousAccount.primaryEmail)"
                IsError = $false;
            });

            $splat = [ordered]@{
                body = [System.Text.Encoding]::UTF8.GetBytes(($account | ConvertTo-Json -Depth 10))
                Uri = "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" 
                Method = 'PUT'
                Headers = $authorization 
                Verbose = $False
            }
            $newAccount = Invoke-RestMethod @splat
            
            $auditLogs.Add([PSCustomObject]@{
                Action = "UpdateAccount"
                Message = "Updated Existing Account"
                IsError = $false;
            });

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
            $calcPrimaryEmailResponse = Invoke-RestMethod @splat

            if($calcPrimaryEmailResponse.users.count -gt 0)
            {
                #Iterate
                Write-Verbose -Verbose "$($account.primaryEmail) already in use, iterating)"
                $Iterator++
                $calcPrimaryEmail = New-PrimaryEmail -person $p -domain $defaultDomain -Iteration $Iterator
                $account.primaryEmail = $calcPrimaryEmail
                Write-Verbose -Verbose "Iteration $($Iterator) - $($account.primaryEmail)"
            }
        } while ($calcPrimaryEmailResponse.users.count -gt 0 -AND $Iterator -lt $maxUsernameIterations)
        
        #Check for exceeding max namegen iterations
        if($Iterator -ge $maxUsernameIterations)
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
                Body = [System.Text.Encoding]::UTF8.GetBytes(($account | ConvertTo-Json -Depth 10))
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

            $auditLogs.Add([PSCustomObject]@{
                Action = "CreateAccount"
                Message = "Created account with PrimaryEmail $($newAccount.primaryEmail)"
                IsError = $false;
            });
        }
        else
        {
            $newAccount = $account;
        }
    }
    $success = $True
}catch{
    $auditLogs.Add([PSCustomObject]@{
                Action = "CreateAccount"
                Message = "Error creating account with PrimaryEmail $($account.primaryEmail) - Error: $($_)"
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
    Account = $newAccount
    PreviousAccount = $previousAccount
    
    # Optionally return data for use in other systems
    ExportData = [PSCustomObject]@{
        PrimaryEmail = $newAccount.PrimaryEmail
        OrgUnitPath = $newAccount.orgUnitPath
    }
}
    
Write-Output ($result | ConvertTo-Json -Depth 10)
#endregion build up result