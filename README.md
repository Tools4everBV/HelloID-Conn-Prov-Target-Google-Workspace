# HelloID-Conn-Prov-Target-GSuite
HelloID Provisioning Target Connector for Google GSuite

In this example we are going to connect to the Google API using OAuth2.0 and the Powershell Invoke-RestMethod cmdlet. Before we can start scripting in Powershell using the example script below, we first need to get a ClientId, ClientSecret, AuthCode and finally the Access and Refresh tokens.

Getting the Google API access
Go to Google Developers Console and create a new project by clicking on the top bar and choose new project.
Give your project a name and click create.
When you are done, click the top bar again and select your newly created project.
You will see the empty dashboard where we need to select which API we want to interact with, In this example we are managing user accounts so we selected the Admin SDK. Click Enable after which you will be redirected back to the dashboard.

As stated on the dashboard, go to the credentials menu item and click on + Create Credentials and choose OAuth client ID.

Application type choose Web application.
Fill in a name you like for the OAuth 2.0 client ID.
For Authorized redirect URIs you can specify http://localhost/oauth2callback
Click create the OAuth 2.0 consent screen and we will get the credentials from the credentials page.
The Client ID and Client secret of the new OAuth client we use in the example scripts below.


Getting the authorization code
With the authorization code, we can get the refresh token. We only need the refresh token, so the easiest way to get this one is to opening the endpoint in the browser, authenticate and grab the code from the address bar.

To get the authorization code please use the URL below and replace the <replaceclientid> and <replaceredirecturi> with the values from the OAuth client we created before.


https://accounts.google.com/o/oauth2/auth?client_id=<replaceclientid>&scope=https://www.googleapis.com/auth/admin.directory.user https://www.googleapis.com/auth/admin.directory.group&response_type=code&redirect_uri=<replaceredirecturi>&access_type=offline&approval_prompt=force

After you have been authenticated, the tequest will be redirected to http://localhost/oauth2callback?code=4/QhUXhB********************z9jGKkhvac2&. Copy the code without the & at the end and store it somewhere, we will need this one later.

Getting the refreshtoken
To exchange the Authorization code for the refresh token, we will use Powershell to make a call to https://www.googleapis.com/oauth2/v4/token. 
Fill in Authorization code, ClienId, Client Secret and redirect Uri from the Google Developer Console and run the PowerShell script below. It will store the refresh token in a text file so you can use it later on.

The claimed authorization code can be exchanged for a refreshtoken only once, otherwise you have to request a new athorization code as described above.
