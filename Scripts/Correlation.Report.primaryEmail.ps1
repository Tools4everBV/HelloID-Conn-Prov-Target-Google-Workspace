## Correlation Report by primaryEmail
## The purpose of this script is to pull in Source Data and check if we can link
## existing accounts by generated email address. It will then report any accounts/persons
## that match up, need to be created, or we have multiple matches for.

## Instructions
## 1. Update Google API Setings
## 2. Add Source Data
## 3. Update $username for the generated username match on

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

    #Get Google Users
        $gsuiteUsers = [System.Collections.ArrayList]@();

        $parameters = @{
                    customer = "my_customer";
                    projection="FULL";
                }

        Write-Verbose -Verbose "Retrieving Users"
        while($true)
        {
            $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users" -Body $parameters -Method GET -Headers $authorization
            $parameters['pageToken'] = $response.nextPageToken;

            [void]$gsuiteusers.AddRange($response.users);
            Write-Verbose -Verbose "$($gsuiteUsers.count) user(s)"
            if($null -eq $parameters['pageToken']) { break; }
        }
        Write-Verbose -Verbose "Retrieve Users";



#Compare
    $results = @{
                    create = [System.Collections.ArrayList]@();
                    match = [System.Collections.ArrayList]@();
    }

    $i = 1;
    foreach($person in $persons)
    {
        Write-Verbose -Verbose "$($i):$($persons.count)";
        $result = $null;
        $username = "$($person.first_name).$($person.last_name)@domain.com"

        foreach($gsuiteUser in $gsuiteUsers)
        {
            if($gsuiteUser.primaryEmail -eq $username)
            {
                $result = [PSCustomObject]@{ id = $person.ID; email = $gsuiteUser.primaryEmail; userId = $gsuiteUser.id; }
                [void]$results.match.Add($result);
                break;
            }
        }

        if($null -eq $result) { [void]$results.create.Add($person) }
        $i++;
    }

#Duplicate Correlations
    $duplicates = [System.Collections.ArrayList]@();
    $duplicatesbyUserId = ($results.match | Group-Object -Property userId) | Where-Object { $_.Count -gt 1 }
    if($duplicatesbyUserId -is [System.Array]) { [void]$duplicates.AddRange($duplicatesbyUserId) } else { [void]$duplicates.Add($duplicatesbyUserId) };
    $duplicatesbyId = ($results.match | Group-Object -Property Id) | Where-Object { $_.Count -gt 1 }
    if($duplicatesbyId -is [System.Array]) { [void]$duplicates.AddRange($duplicatesbyId) } else { [void]$duplicates.Add($duplicatesbyId) };

#Results
    Write-Verbose -Verbose "$($results.create.count) Create(s)"
    Write-Verbose -Verbose "$($results.match.count) Correlation(s)"
    Write-Verbose -Verbose "$($duplicates.count) Duplicate Correlation(s)"

    $results.create | Out-GridView
    if($duplicates.count -gt 0) { $duplicates | Out-GridView }
