$requestUri = "https://www.googleapis.com/oauth2/v4/token"
$clientId = "<put your client id here>"
$clientSecret = "<put your client secret here>"
$redirectUri = "http://localhost/oauth2callback"

$code = "<put your authorization code here>"

$body = @{
    code=$code;
    client_id=$clientId;
    client_secret=$clientSecret;
    redirect_uri=$redirectUri;
    grant_type="authorization_code"; # Fixed value
};

$tokens = Invoke-RestMethod -Uri $requestUri -Method POST -Body $body;

# Store refreshToken
Set-Content $PSScriptRoot"\refreshToken.txt" $tokens.refresh_token
