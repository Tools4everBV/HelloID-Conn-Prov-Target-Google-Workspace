$retrievedPermissions = @(
    @{
        name      = 'Google Workspace Business Starter'
        id        = '1010020027'
        productId = 'Google-Apps'
    },
    @{
        name      = 'Google Workspace Business Standard'
        id        = '1010020028'
        productId = 'Google-Apps'
    },
    @{
        name      = 'Google Workspace Business Plus'
        id        = '1010020025'
        productId = 'Google-Apps'
    },
    @{
        name      = 'Google Workspace Enterprise Essentials'
        id        = '1010060003'
        productId = 'Google-Apps'
    },
    @{
        name      = 'Google Workspace Enterprise Starter'
        id        = '1010020029'
        productId = 'Google-Apps'
    },
    @{
        name      = 'Google Workspace Enterprise Standard'
        id        = '1010020026'
        productId = 'Google-Apps'
    },
    @{
        name      = 'Google Workspace Enterprise Plus (formerly G Suite Enterprise)'
        id        = '1010020020'
        productId = 'Google-Apps'
    },
    # "Invalid productId: Google-Apps"
    # Google Workspace Essentials is not part of the main Google Workspace family. It's a distinct product with its own SKU (1010060001)
    @{
        name      = 'Google Workspace Essentials (formerly G Suite Essentials)'
        id        = '1010060001'
        productId = '101006'
    },
    @{
        name      = 'Google Workspace Enterprise Essentials Plus'
        id        = '1010060005'
        productId = 'Google-Apps'
    },
    @{
        name      = 'Google Workspace Frontline Starter'
        id        = '1010020030'
        productId = 'Google-Apps'
    },
    @{
        name      = 'Google Workspace Frontline Standard'
        id        = '1010020031'
        productId = 'Google-Apps'
    }
)

#################################################
# HelloID-Conn-Prov-Target-Google-Permissions-Licenses-Import
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
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
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
            } else {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
        } catch {
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
    } catch {
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
        } catch {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
}
#endregion functions

try {
    Write-Information 'Starting license data import'
    Write-Information 'Getting JWT token'
    $splatGetGoogleWSTokenParams = @{
        Issuer                 = $actionContext.Configuration.Issuer
        Subject                = $actionContext.Configuration.Subject
        Scopes                 = @('https://www.googleapis.com/auth/apps.licensing', 'https://www.googleapis.com/auth/admin.directory.user')
        P12CertificateBase64   = $actionContext.Configuration.P12CertificateBase64
        P12CertificatePassword = $actionContext.Configuration.P12CertificatePassword
    }
    $accessToken = Get-GoogleWSAccessToken @splatGetGoogleWSTokenParams

    Write-Information 'Setting authentication headers'
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Content-Type', 'application/x-www-form-urlencoded')
    $headers.Add('Authorization', "Bearer $($accessToken)")

    Write-Information 'Retrieve Static GoogleWS licenses'
    $retrievedPermissions = $retrievedPermissions

    foreach ($retrievedPermission in $retrievedPermissions) {
        $permission = @{
            PermissionReference = @{
                Reference = $retrievedPermission.id
            }
            Description         = "$($retrievedPermission.name)"
            DisplayName         = "$($retrievedPermission.name)"
            AccountReference    = $null
        }
        try {
            $splatGetLicenseMembers = @{
                Uri     = "https://www.googleapis.com/apps/licensing/v1/product/$($retrievedPermission.productId)/sku/$($retrievedPermission.id)/users?customerId=$($actionContext.Configuration.CustomerId)"
                Method  = 'GET'
                Headers = $headers
            }
            $membersOfRetrievedPermission = [System.Collections.Generic.List[string]]((Invoke-GoogleWSRestMethodWithPaging @splatGetLicenseMembers -CollectionName 'items').userId)
        } catch {
            throw $_
        }

        # Batch permissions based on AccountReference to ensure the output object do not exceed the limit.
        $batchSize = 500
        for ($i = 0; $i -lt $membersOfRetrievedPermission.Count; $i += $batchSize) {
            # GetRange instead of `| Select-Object -First -Skip` to avoid issues with large lists.
            $permission.AccountReferences = [array]($membersOfRetrievedPermission.GetRange($i, [Math]::Min($batchSize, $membersOfRetrievedPermission.Count - $i)))
            Write-Output $permission
        }
    }
    Write-Information 'License data import completed'
} catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-GoogleWSError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import Google License. Error: $($errorObj.FriendlyMessage)"
    } else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import Google License. Error: $($ex.Exception.Message)"
    }
}
