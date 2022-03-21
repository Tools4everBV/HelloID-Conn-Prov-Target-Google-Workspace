$config = ConvertFrom-Json $configuration

# The resourceData used in this default script uses resources based on Title
$rRef = $resourceContext | ConvertFrom-Json
$success = $false

$auditLogs = [Collections.Generic.List[PSCustomObject]]@()

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
    $response = Invoke-RestMethod -Method Post -Uri $requestUri -Body $refreshTokenParams -Verbose:$False
    $accessToken = $response.access_token

    #Add the authorization header to the request
    $authorization = [ordered]@{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }
    $authorization
}
#endregion Support Functions

# Get the authorization header
$authorization = Get-GoogleAccessToken

# In preview only the first 10 items of the SourceData are used
foreach ($title in $rRef.SourceData) {
    
    $calc_title = $title;
    $calc_title = $calc_title -replace '\s','_' #Remove Spaces 
    $calc_title = $calc_title -replace '[^a-zA-Z0-9_]', '' #Remove Special Characters, except underscore
    $calc_title = $calc_title -replace '__','_' #Remove Double Underscores 
    $calc_groupName = "IAM_POSD_$($calc_title)"

    if($calc_groupName -eq "IAM_POSD_") { continue }
        
    #Check if Group Exists
    try{
            #Write-Information "Checking $($calc_groupName)"
            $splat = @{
                Body = @{
                    customer = "my_customer"
                    query    = "Email:{0}@*" -f $calc_groupName
                }
                URI = "https://www.googleapis.com/admin/directory/v1/groups"
                Method = 'GET'
                Headers = $authorization 
                Verbose = $False
            }
            $groupResponse = Invoke-RestMethod @splat
    } catch {}

    if($groupResponse.groups)
    {
        #Already exists
        #Write-Information "$($calc_groupName) Exists"
    }
    else {
        # If resource does not exist
        <# Resource creation preview uses a timeout of 30 seconds
        while actual run has timeout of 10 minutes #>
        Write-Information "Creating $($calc_groupName)"

        if (-Not($dryRun -eq $True)) {
            try{
                $group = @{
                        name = $calc_groupName
                        email    = "{0}@{1}" -f $calc_groupName, $config.defaultDomain
                    }
                $splat = @{
                    Body = [System.Text.Encoding]::UTF8.GetBytes(($group | ConvertTo-Json))
                    URI = "https://www.googleapis.com/admin/directory/v1/groups"
                    Method = 'POST'
                    Headers = $authorization 
                    Verbose = $False
                }
                
                $groupResponse = Invoke-RestMethod @splat
                $success = $True
            } catch {
                Write-Error "Failed to Create $($calc_groupName) - $_"
            }
        }

        $auditLogs.Add([PSCustomObject]@{
            Message = "Creating resource for title $($title.name) - $calc_groupName"
            Action  = "CreateResource"
            IsError = $false
        })
    }   
}

$success = $true

# Send results
$result = [PSCustomObject]@{
    Success   = $success
    AuditLogs = $auditLogs
}

Write-Output $result | ConvertTo-Json -Depth 10