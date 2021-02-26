# Active Directory mail attribute, check Google GSuite Email Addresses
# 1. Checks for Correlated accounts
####  - If Correlated Account(s) is available check to see if assigned. If already assigned, Success
# 2. Check all Google GSuite email addresses for conflict
####  - If there is a conflict then Uniqueness will Fail. Else Success

# Initialize default properties
$p = $person | ConvertFrom-Json;
$a = $account | ConvertFrom-Json;

if($dryRun -eq $True) {
    Write-Verbose -Verbose "Dry run for uniqueness check on external systems"
}

$config = @{ 
            clientId = "";
            clientSecret = "";
            redirectUri = "http://localhost/oauth2callback";
            refreshToken = "";
}

try{
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

    #Check for correlated accounts
     $parameters = @{
        customer = "my_customer";
        query = "externalId=$($p.ExternalId)";
        projection="FULL";
    }
    $correlationResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Method GET -Body $parameters -Headers $authorization -Verbose:$false;
    
    if($correlationResponse.users.count -gt 0)
    {
        if($correlationResponse.users.count -gt 1)
        {
             Write-Verbose "Multiple Correlated Accounts found" -Verbose
        }
        else
        {
            Write-Verbose "Correlated Account found" -Verbose
        }
        
        $existingEmails = $correlationResponse.users.emails | Select -ExpandProperty Address;
        
    }

    if($existingEmails -contains $a.AdditionalFields.mail)
    {
            $success = $True;
            Write-Verbose -Verbose "$($a.AdditionalFields.mail) is unique in Google GSuite [Correlated]"
            $NonUniqueFields = @();
    }
    else
    {
        $uniquenessResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Method GET -Body $parameters -Headers $authorization -Verbose:$false;

        #Check if account exists (externalId), else create
        $parameters = @{
            customer = "my_customer";
            query = "email=$($a.AdditionalFields.mail)";
            projection="FULL";
        }

        $uniquenessResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Method GET -Body $parameters -Headers $authorization -Verbose:$false;

        if($uniquenessResponse.users.count -gt 0)
        {
            $success = $False;
            Write-Verbose -Verbose "$($a.AdditionalFields.mail) is not unique in Google GSuite [Conflict]"
            $NonUniqueFields = @("mail");
        }
        else
        {
            $success = $True;
            Write-Verbose -Verbose "$($a.AdditionalFields.mail) is unique in Google GSuite [No Match]"
            $NonUniqueFields = @();
        }
    }
}
catch
{
    Write-Verbose -Verbose "Failed to Check Google GSuite for uniqueness"
    Write-Verbose -Verbose $_;
    $success = $false;
    $NonUniqueFields = @("mail");
}

# Build up result
$result = [PSCustomObject]@{
    Success = $success;
    # Add field name as string when field is not unique
    NonUniqueFields = $NonUniqueFields;
};

# Send result back
Write-Output $result | ConvertTo-Json -Depth 2
