#################################################
# HelloID-Conn-Prov-Target-Google-Permissions-Groups-Import
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Resolve-GoogleWSError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            if (-NOT([String]::IsNullOrEmpty(($errorDetailsObject.error | Select-Object -First 1).message))) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error.message -join ', '
            }
            else {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}
function Get-GoogleWSAccessToken {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $Issuer,

        [Parameter()]
        [string]
        $Subject,

        [Parameter()]
        [string[]]$Scopes,

        [Parameter()]
        [string]
        $P12CertificateBase64,

        [Parameter()]
        [string]
        $P12CertificatePassword
    )

    try {
        $now = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]"1970-01-01T00:00:00Z").ToUniversalTime()).TotalSeconds)
        $jwtHeader = @{
            alg = 'RS256'
            typ = 'JWT'
        } | ConvertTo-Json
        $jwtBase64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($jwtHeader))

        $jwtPayload = [Ordered]@{
            iss   = $Issuer
            sub   = $Subject
            scope = $($Scopes -join " ")
            aud   = "https://www.googleapis.com/oauth2/v4/token"
            exp   = $now + 3600
            iat   = $now
        } | ConvertTo-Json
        $jwtBase64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($jwtPayload))

        $rawP12Certificate = [system.convert]::FromBase64String($P12CertificateBase64)
        $p12Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawP12Certificate, $P12CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $rsaPrivate = $P12Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))
        $signatureInput = "$jwtBase64Header.$jwtBase64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), "SHA256")
        $base64Signature = [System.Convert]::ToBase64String($signature)
        $jwtToken = "$signatureInput.$base64Signature"

        $splatParams = @{
            Uri         = 'https://www.googleapis.com/oauth2/v4/token'
            Method      = 'POST'
            Body        = @{
                grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
                assertion  = $jwtToken
            }
            ContentType = 'application/x-www-form-urlencoded'
        }
        $response = Invoke-RestMethod @splatParams
        $response.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Invoke-GoogleWSRestMethodWithPaging {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $Headers,

        [Parameter(Mandatory)]
        [string]
        $CollectionName
    )
    process {
        $maxResults = 200
        $returnList = [System.Collections.Generic.List[Object]]::new()
        try {
            do {
                # Append Skip Take parameters
                $urlWithOffSet = $Uri + "?maxResults=$maxResults"
                if ($Uri.Contains('?')) {
                    $urlWithOffSet = $Uri + "&maxResults=$maxResults"
                }
                if ($partialResult.nextPageToken) {
                    $urlWithOffset += "&pageToken=$($partialResult.nextPageToken)"
                }
                $splatParams = @{
                    Uri     = $urlWithOffset
                    Headers = $Headers
                    Method  = $Method
                }
                $partialResult = Invoke-RestMethod @splatParams -Verbose:$false
                if ($partialResult.$CollectionName.Count -gt 0) {
                    $returnList.AddRange($partialResult.$CollectionName)
                }

            } until ($null -eq $partialResult.nextPageToken)
            Write-Output $returnList -NoEnumerate
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
#endregion functions

try {
    Write-Information 'Starting group data import'
    $splatGetGoogleWSTokenParams = @{
        Issuer                 = $ActionContext.Configuration.Issuer
        Subject                = $ActionContext.Configuration.Subject
        Scopes                 = @(
            'https://www.googleapis.com/auth/admin.directory.group'
            , 'https://www.googleapis.com/auth/admin.directory.user'
        )
        P12CertificateBase64   = $ActionContext.Configuration.P12CertificateBase64
        P12CertificatePassword = $ActionContext.Configuration.P12CertificatePassword
    }
    $accessToken = Get-GoogleWSAccessToken @splatGetGoogleWSTokenParams

    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Content-Type', 'application/x-www-form-urlencoded')
    $headers.Add('Authorization', "Bearer $($accessToken)")

    $splatGetGroups = @{
        Uri     = "https://www.googleapis.com/admin/directory/v1/groups?customer=my_customer"
        Method  = 'GET'
        Headers = $headers
    }
    $retrievedPermissions = Invoke-GoogleWSRestMethodWithPaging @splatGetGroups -CollectionName 'groups'
    Write-Information "Queried groups. Result count: $(($retrievedPermissions | Measure-Object).Count)"

    $splatGetUserParams = @{
        Uri     = 'https://www.googleapis.com/admin/directory/v1/users?customer=my_customer'
        Method  = 'GET'
        Headers = $headers
    }
    $importedAccounts = (Invoke-GoogleWSRestMethodWithPaging @splatGetUserParams -CollectionName 'Users').id
    Write-Information "Queried accounts. Result count: $(($importedAccounts | Measure-Object).Count)"

    # Process each group and output permission objects with filtered account references
    $importedPermissions = 0
    foreach ($retrievedPermission in $retrievedPermissions) {
        $permission = @{
            PermissionReference = @{
                Reference = $retrievedPermission.id
            }
            AccountReferences   = $null
        }

        if ($retrievedPermission.directMembersCount -gt 0) {
            $splatGetGroupMembers = @{
                Uri     = "https://www.googleapis.com/admin/directory/v1/groups/$($retrievedPermission.id)/members?customer=my_customer&roles=member"
                Method  = 'GET'
                Headers = $headers
            }
            $membersOfRetrievedPermission = (Invoke-GoogleWSRestMethodWithPaging @splatGetGroupMembers -CollectionName 'members')#.id
            # Filter the members to only include those that exist in the imported accounts
            $membersOfRetrievedPermission = $membersOfRetrievedPermission | Where-Object { $_ -in $importedAccounts }

            # The code below splits a list of permission members into batches of 100
            # Each batch is assigned to $permission.AccountReferences and the permission object will be returned to HelloID for each batch
            # Ensure batching is based on the number of account references to prevent exceeding the maximum limit of 500 account references per batch
            $batchSize = 500
            for ($i = 0; $i -lt ($membersOfRetrievedPermission | Measure-Object).Count; $i += $batchSize) {
                $permission.AccountReferences = $membersOfRetrievedPermission[$i..([Math]::Min($i + $batchSize - 1, $membersOfRetrievedPermission.Count - 1))]
                Write-Output $permission
            }

            $importedPermissions += ($membersOfRetrievedPermission | Measure-Object).Count
        }
    }
    
    Write-Information "Completed import of group permissions. Result count: $importedPermissions"
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-GoogleWSError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import Google Groups. Error: $($errorObj.FriendlyMessage)"
    }
    else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import Google Groups. Error: $($ex.Exception.Message)"
    }
}