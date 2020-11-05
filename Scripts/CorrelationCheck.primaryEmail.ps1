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
            if($parameters['pageToken'] -eq $null) { break; }
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
                $result = @{ id = $person.ID; email = $gsuiteUser.primaryEmail; userId = $gsuiteUser.id; }
                [void]$results.match.Add($result);
                break;
            }
        }

        if($result -eq $null) { [void]$results.create.Add($person) }
        $i++;
    }

#Results
    Write-Verbose -Verbose "$($results.create.count) Create(s)"
    Write-Verbose -Verbose "$($results.match.count) Correlation(s)"
    $results.create | Out-GridView
