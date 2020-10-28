#2020-10-28
$config = ConvertFrom-Json $configuration;
 
#Initialize default properties
$success = $False;
$p = $person | ConvertFrom-Json
$auditMessage = "Account for person $($p.DisplayName) not created successfully";
 
#Defaults, create only
$defaultPassword = [System.Web.Security.Membership]::GeneratePassword(10, 0); ##Method doesn't work with cloud agent.
$defaultDomain = "yourdomain.com";
$defaultOrgUnitPath = "/Disabled";
$defaultSuspended = $true;

#Primary Email Generation
# 1. <First Name>.<Last Name>@<Domain> (e.g john.williams@yourdomain.com)
# 2. <First Name>.<Last Name><Iterator>@<Domain> (e.g john.williams01@yourdomain.com)
function get_username {
[cmdletbinding()]
Param (
[string]$firstName,
[string]$lastName,
[string]$domain,
[int]$Iteration
   ) 
    Process 
    {
        $suffix = "";
        if($Iteration -gt 0) { $suffix = ("00$($Iteration+1)").substring(1,2); };
        
        $temp_fn = $firstName;
        $temp_ln = $lastName;
        $temp_username = $temp_fn + "." + $temp_ln;
        
        $result = $temp_username + $suffix + $domain;
        $result = $result.toLower();
        @($result);
    }
}

$username = get_username -firstName $p.Name.NickName -lastName $p.Name.FamilyName -domain $defaultDomain -Iteration 0;

#Change mapping here
#For all of the supported attributes please check https://developers.google.com/admin-sdk/directory/v1/guides/manage-users
$account = @{
    primaryEmail = $username
    name = @{
                givenName = "$($p.Name.NickName)"
                familyName = "$($p.Name.FamilyName)"
                fullName = "$($p.Name.NickName) $($p.Name.FamilyName)"
            }
    externalIds =  @(@{
                        value = "$($p.ExternalId)"
                        type = "organization";
                    })
    organizations = @(@{
                        title = "$($p.primaryContract.Title.name)"
                        #department = "$($p.primaryContract.custom.TeamDesc)"
                        #costCenter = "$($p.primaryContract.costCenter.ExternalID)"
                    })
}

# exchange the refresh token for an access token
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
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    #Check if account exists (externalId), else create
    $parameters = @{
        customer = "my_customer";
        query = "externalId=$($p.ExternalId)";
        projection="FULL";
    }
    $correlationResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Method GET -Body $parameters -Headers $authorization -Verbose:$false;
    
    if($correlationResponse.users.count -gt 0)
    {
        Write-Verbose -Message "Existing Account found" -Verbose
        
        $aRef = $correlationResponse.users[0].id;
        
        #Use existing primaryEmail
        $account.primaryEmail = $correlationResponse.users[0].primaryEmail;
        $body = $account | ConvertTo-Json -Depth 10
        
        if(-Not($dryRun -eq $True)){
           $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" -Method PUT -Headers $authorization -Body $body -Verbose:$false
        }
    }
    else
    {
        $Iterator = 0;
        while($true)
        {
            #Check if username taken
            $parameters = @{
               customer = "my_customer";
               query = "Email=$($account.primaryEmail)";
               projection="FULL";
           }
            $usernameResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Method GET -Body $parameters -Headers $authorization -Verbose:$false

            if($usernameResponse.users.count -gt 0)
            {
                #Iterate
                Write-Verbose -Verbose "$($account.primaryEmail) already in use, iterating)"
                $Iterator++;
                $account.primaryEmail = get_username -firstName $p.Name.NickName -lastName $p.Name.FamilyName -domain $defaultDomain -Iteration $Iterator;
            }
            else
            {
                #Username available
                break;
            }
        }
        
        #Safe measure, set defaults 
        $account.password = $defaultPassword;
        $account.orgUnitPath = $defaultOrgUnitPath;
        $account.suspended = $defaultSuspended;
        
        if(-Not($dryRun -eq $True)){
           $body = $account | ConvertTo-Json -Depth 10
           $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$($aRef)" -Method POST -Headers $authorization -Body $body -Verbose:$false
           $aRef = $response.id
        }
    }
    $success = $True;
    $auditMessage = " successfully"; 
}catch{
    $auditMessage = " : General error $($_)";
    Write-Error -Verbose $_; 
}
 
#build up result
$result = [PSCustomObject]@{
    Success= $success;
    AccountReference= $aRef;
    AuditDetails=$auditMessage;
    Account= $account;
};
  
Write-Output $result | ConvertTo-Json -Depth 10;
