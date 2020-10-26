#2020-10-26
$config = ConvertFrom-Json $configuration;
 
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
$gsuiteGroups = [System.Collections.ArrayList]@();
$nextPageToken = 'first';
while($true)
{
    if($nextPageToken -eq 'first')
    {
        $parameters = @{
            customer = "my_customer";
        }
        $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/groups" -Body $parameters -Method GET -Headers $authorization
        $nextPageToken = $response.nextPageToken;
    }
    else
    {
        $parameters = @{
            customer = "my_customer";
            pageToken = "$($nextPageToken)"
        }
        $response = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/groups" -Body $parameters -Method GET -Headers $authorization;
        $nextPageToken = $response.nextPageToken;
    }
 
    [void]$gsuiteGroups.AddRange($response.groups);
    if($nextPageToken -eq $null) { break; }
}
 
foreach($group in $gsuiteGroups)
{
    $row = @{
                DisplayName = $group.name;
                Identification = @{
                                    Id = $group.id;
                                    DisplayName = $group.name;
                }
    };
 
    Write-Output $row | ConvertTo-Json -Depth 10
}
