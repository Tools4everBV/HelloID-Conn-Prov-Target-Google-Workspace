## Correlate Account
## The purpose of this example script is to update the externalId(s)
## for a Google Suite User using a CSV. Please see ignoreExistingData flag
## it will overwrite any existing ExternalId's. The specific field set in
## the google admin is "Employee ID"

## Instructions
## 1. Update Settings

#Settings
$config = @{ 
                #clientId = "{GOOGLE CLIENT ID}";
                #clientSecret = "{GOOGLE CLIENT SECRET}";
                #redirectUri = "http://localhost/oauth2callback";
                #refreshToken = "{GOOGLE REFRESH TOKEN}";
                ignoreExistingData = $false;
                csvPath = "C:\temp\GoogleLink.csv"; # two columns: ID, userKey
            }

#Import Data
    $data = Import-Csv $config.csvPath;

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

#Process Users
    $i=1;
    foreach($item in $data)
    {
        Write-Verbose -Verbose "$($i):$($data.count)"
        $body = $null;
        if($config.ignoreExistingData -eq $true)
        {
            #Overwriting any existing externalId's
            $body = @{ externalIds =  @(
                                                @{
                                                    value = "$($item.id)"
                                                    type = "organization";
                                                 }
                                             )
                           }
        }
        else
        {
            #Retrieve Existing User
            $parameters = @{
                                projection = "custom";
                                fields = "id,primaryEmail,externalIds";
                           }
            $existingUser = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$($item.userKey)" -Body $parameters -Method GET -Headers $authorization
            
            if($existingUser.externalIds -eq $null)
            {
                #No Existing externalIds, Only New ID
                $body =  @{ externalIds =  @(
                                                @{
                                                    value = "$($item.id)"
                                                    type = "organization";
                                                 }
                                             )
                           }
            }
            else
            {
                #Setup New ID
                $body = @{ externalIds = [System.Collections.ArrayList]@(@{ value = "$($item.id)"; type = "organization"; }) }
                
                ##Add Existing
                foreach($extId in $existingUser.externalIds)
                {
                    [void]$body.externalIds.Add($extId);
                } 
            }
            
        }
        
        #Update User
        $updatedUser = Invoke-RestMethod -Uri "https://www.googleapis.com/admin/directory/v1/users/$($item.userKey)" -Body ($body | ConvertTo-Json) -Method PUT -Headers $authorization
        $i++;
    }
