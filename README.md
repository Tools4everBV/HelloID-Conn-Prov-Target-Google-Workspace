# HelloID-Conn-Prov-Target-GSuite
In this example we are going to connect to the Google Directory API (https://developers.google.com/admin-sdk/directory) using OAuth2.0 and the Powershell.

## Setting up the Google API access
 1. Go to Google Developers Console and create a new project by clicking on the top bar and choose new project. Give your project a name and click create. When you are done, click the top bar again and select your newly created project.
 2. You will see the empty dashboard where we need to select which API we want to interact with, In this example we are managing user accounts so we selected the Admin SDK. Click Enable after which you will be redirected back to the dashboard.
 3. As stated on the dashboard, go to the credentials menu item and click on + Create Credentials and choose OAuth client ID.
 4. Application type choose Web application.
 5. Fill in a name you like for the OAuth 2.0 client ID.
 6. For Authorized redirect URIs you can specify http://localhost/oauth2callback
 7. Click create the OAuth 2.0 consent screen and we will get the credentials from the credentials page.
 8. The Client ID and Client secret of the new OAuth client we use in the example scripts below.


## Getting the authorization code
With the authorization code, we can get the refresh token. We only need the refresh token. 
1. To get the authorization code please use the URL below and replace the {replaceclientid} with the values from the OAuth client we created before.
```
https://accounts.google.com/o/oauth2/auth?client_id={replaceclientid}&scope=https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/admin.directory.group&response_type=code&redirect_uri=http://localhost/oauth2callback&access_type=offline&approval_prompt=force
```
2. Open the URL in a webbrowser of your choosing.
3. The browser will be redirected to the redirect URI. We will need to copy the code value out of the URL in the address bar, so we can obtain a refresh token in the next section.
```
Example
http://localhost/oauth2callback?code=4/QhUXhB********************z9jGKkhvac2&
The code would be 4/QhUXhB********************z9jGKkhvac2&
```

## Getting the refreshtoken
1. To exchange the Authorization code for the refresh token, we will use Powershell to make a call to https://www.googleapis.com/oauth2/v4/token. 
2. Fill in Authorization code, Client Id, Client Secret and Redirect Uri from the Google Developer Console and run the refreshtoken.ps1 in the repo. It will store the refresh token in a text file so you can use it later on.

Note: The claimed authorization code can be exchanged for a refreshtoken only once, otherwise you have to request a new athorization code as described above.
