# Active Directory mail attribute, check Google GSuite Email Addresses
# 1. Checks for Correlated accounts
####  - If Correlated Account(s) is available check to see if assigned. If already assigned, Success
# 2. Check all Google GSuite email addresses for conflict
####  - If there is a conflict then Uniqueness will Fail. Else Success

#region Initialize default properties
$p = $person | ConvertFrom-Json;
$a = $account | ConvertFrom-Json;
#endregion Initialize default properties

#region Change mapping here
$config = @{
    clientId = "";
    clientSecret = "";
    redirectUri = "http://localhost/oauth2callback";
    refreshToken = "";
    correlationPersonField = $p.ExternalId;
    correlationAccountField = "ExternalId"
    uniqueFieldName = "mail";
    uniqueFieldValue = $a.AdditionalFields.mail;
}
#endregion Change mapping here

#region Execute
if($dryRun -eq $True) {
    Write-Verbose -Verbose "Dry run for uniqueness check on external systems"
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
        query = "$($config.correlationAccountField)=$($config.correlationPersonField)";
        projection="FULL";
    }
    $correlationResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Method GET -Body $parameters -Headers $authorization -Verbose:$false;

    if($correlationResponse.users.count -gt 0)
    {
        if($correlationResponse.users.count -gt 1)
        {
             Write-Verbose -Verbose "Multiple Correlated Accounts found"
        }
        else
        {
            Write-Verbose -Verbose "Correlated Account found"
        }

        $existingEmails = $correlationResponse.users.emails | Select-Object -ExpandProperty Address;

    }

    if($existingEmails -contains $config.uniqueFieldValue)
    {
            $success = $True;
            Write-Verbose -Verbose "$($config.uniqueFieldValue) is unique in Google GSuite [Correlated]"
            $NonUniqueFields = @();
    }
    else
    {
        $uniquenessResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Method GET -Body $parameters -Headers $authorization -Verbose:$false;

        #Check if account exists (externalId), else create
        $parameters = @{
            customer = "my_customer";
            query = "email=$($config.uniqueFieldValue)";
            projection="FULL";
        }

        $uniquenessResponse = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Method GET -Body $parameters -Headers $authorization -Verbose:$false;

        if($uniquenessResponse.users.count -gt 0)
        {
            $success = $False;
            Write-Verbose -Verbose "$($config.uniqueFieldValue) is not unique in Google GSuite [Conflict]"
            $NonUniqueFields = @("mail");
        }
        else
        {
            $success = $True;
            Write-Verbose -Verbose "$($config.uniqueFieldValue) is unique in Google GSuite [No Match]"
            $NonUniqueFields = @();
        }
    }
}
catch
{
    Write-Verbose -Verbose "Failed to Check Google GSuite for uniqueness"
    Write-Verbose -Verbose $_;
    $success = $false;
    $NonUniqueFields = @($config.uniqueFieldName);
}
#endregion Execute

#region Build up result
$result = [PSCustomObject]@{
    Success = $success;
    NonUniqueFields = $NonUniqueFields;
};

Write-Output $result | ConvertTo-Json -Depth 2
#endregion Build up result