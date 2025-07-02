#################################################
# HelloID-Conn-Prov-Target-Google-Import
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

function ConvertTo-HelloIDAccountObject {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $True)]
        [object]
        $GoogleAccountObject
    )

    process {
        if ($null -ne $GoogleAccountObject.organizations) {
            foreach ($organization in $GoogleAccountObject.organizations ) {
                switch ($organization.type) {
                    'work' {
                        $department = $organization.department
                        $title = $organization.title
                    }
                }
            }
        }

        if ($null -ne $GoogleAccountObject.externalIds) {
            foreach ($externalId in $GoogleAccountObject.externalIds ) {
                switch ($externalId.type) {
                    'organization' {
                        $externalId = $externalId.value
                    }
                }
            }
        }

        if ($null -ne $GoogleAccountObject.relations) {
            foreach ($relation in  $GoogleAccountObject.relations) {
                if ($relation.type -eq 'manager') {
                    $manager = $relation.value
                    break
                }
            }
        }

        if ($GoogleAccountObject.IncludeInGlobalAddressList) {
            $includeInGlobalAddressList = 'true'
        }
        else {
            $includeInGlobalAddressList = 'false'
        }

        $mobilePhone = $null
        $workPhone = $null
        foreach ($phone in $GoogleAccountObject.phones ) {
            switch ($phone.type) {
                'mobile' {
                    $mobilePhone = if ([string]::IsNullOrEmpty($phone.value)) { $null } else { $phone.value }
                }
                'work' {
                    $workPhone = if ([string]::IsNullOrEmpty($phone.value)) { $null } else { $phone.value }
                }
            }
        }

        $helloIdAccountObject = [PSCustomObject] @{
            Container                  = "$($GoogleAccountObject.orgUnitPath)"
            Department                 = "$department"
            ExternalID                 = "$externalId"
            FamilyName                 = "$($GoogleAccountObject.name.familyName)"
            GivenName                  = "$($GoogleAccountObject.name.givenName)"
            IncludeInGlobalAddressList = "$includeInGlobalAddressList"
            Manager                    = "$Manager"
            MobilePhone                = $mobilePhone
            PrimaryEmail               = "$($GoogleAccountObject.PrimaryEmail)"
            Title                      = "$title"
            WorkPhone                  = $workPhone
        }
        Write-Output $helloIdAccountObject
    }
}

try {
    Write-Information 'Starting account data import'

    Write-Information 'Getting JWT token'
    $splatGetGoogleWSTokenParams = @{
        Issuer                 = $actionContext.Configuration.Issuer
        Subject                = $actionContext.Configuration.Subject
        Scopes                 = @('https://www.googleapis.com/auth/admin.directory.user')
        P12CertificateBase64   = $actionContext.Configuration.P12CertificateBase64
        P12CertificatePassword = $actionContext.Configuration.P12CertificatePassword
    }
    $accessToken = Get-GoogleWSAccessToken @splatGetGoogleWSTokenParams

    Write-Information 'Setting authentication headers'
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "Bearer $($accessToken)")
    $splatGetUserParams = @{
        Uri     = 'https://www.googleapis.com/admin/directory/v1/users?customer=my_customer'
        Method  = 'GET'
        Headers = $headers
    }
    $importedAccounts = Invoke-GoogleWSRestMethodWithPaging @splatGetUserParams -CollectionName 'Users'

    # Map the imported data to the account field mappings
    foreach ($importedAccount in $importedAccounts) {
        $data = @{}
        $formattedImportAccount = $importedAccount | ConvertTo-HelloIDAccountObject
        foreach ($field in $actionContext.ImportFields) {
            $data[$field] = $formattedImportAccount.$field
        }

        # Custom field mapping
        $isEnabled = $false
        if ( $importedAccount.suspended -eq $false -and $importedAccount.includeInGlobalAddressList -eq $true) {
            $isEnabled = $true
        }

        Write-Output @{
            AccountReference = $importedAccount.Id
            DisplayName      = "$($importedAccount.name.fullName)"
            UserName         = $importedAccount.primaryEmail
            Enabled          = $isEnabled
            Data             = $data
        }
    }

    Write-Information 'Account data import completed'
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-GoogleWSError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import Google accounts. Error: $($errorObj.FriendlyMessage)"
    }
    else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import Google accounts. Error: $($ex.Exception.Message)"
    }
}