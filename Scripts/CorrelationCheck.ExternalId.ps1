## Correlation Report by externalId
## The purpose of this script is to pull in Source Data and check if we can link
## existing accounts by id. It will then report any accounts/persons
## that match up, need to be created, or we have multiple matches for.

## Instructions
## 1. Update Google API Setings
## 2. Add Source Data
## 3. Update Request Query to select the proper ID field
## 3a. If ID field is changed update $result ID field as well.

#Settings
$config = @{ 
                clientId = "{GOOGLE CLIENT ID}";
                clientSecret = "{GOOGLE CLIENT SECRET}";
                redirectUri = "http://localhost/oauth2callback";
                refreshToken = "{GOOGLE REFRESH TOKEN}";
            }

 #Source Data
    Write-Verbose -Verbose "Retrieving Source data";
    $persons = [System.Collections.ArrayList]@();
    Write-Verbose -Verbose "$($persons.count) source record(s)";

#GSuite
    #Authorization
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
#Compare
    $results = @{
                    create = [System.Collections.ArrayList]@();
                    match = [System.Collections.ArrayList]@();
    }

    $i = 1;
    foreach($person in $persons)
    {
        Write-Verbose -Verbose "$($i):$($persons.count)";
        $result = $null
        
        #Check if account exists (externalId), else create
        $parameters = @{
            customer = "my_customer";
            query = "externalId=$($person.ID)";
            projection="FULL";
        }
        $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Method GET -Body $parameters -Headers $authorization -Verbose:$false;
    
        foreach($r in $response.users)
        {
            $result = [PSCustomObject]@{ id = $person.ID; email = $r.primaryEmail; userId = $r.id; person = $person; gsuiteUser = $r; }
            [void]$results.match.Add($result);
        }
               
        if($response.users -eq $null) { [void]$results.create.Add($person) }
        $i++;
        
    }

#Duplicate Correlations
    $duplicates = ($results.match | Group-Object -Property userId) | Where-Object { $_.Count -gt 1 } 

#Results
    Write-Verbose -Verbose "$($results.create.count) Create(s)"
    Write-Verbose -Verbose "$($results.match.count) Correlation(s)"
    Write-Verbose -Verbose "$($duplicates.count) Duplicate Correlation(s)"

    $results.create | Out-GridView
    if($duplicates.count -gt 0) { $duplicates | Out-GridView } 
