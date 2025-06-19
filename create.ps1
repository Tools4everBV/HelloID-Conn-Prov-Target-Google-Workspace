#################################################
# HelloID-Conn-Prov-Target-GoogleWorkSpace-Create
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

function New-GoogleAccountObject {
    [CmdletBinding()]
    param (
    )

    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($($actionContext.Data.Password))
    $sHA1Hash = [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash($passwordBytes)
    $sHA1HashString = [BitConverter]::ToString($SHA1Hash) -replace '-'

    $organizations = @()
    if (-not [string]::IsNullOrWhiteSpace($actionContext.Data.Department)) {
        $organizations = @(@{
                title      = "$($actionContext.Data.Title)"
                department = "$($actionContext.Data.Department)"
                type       = 'work'
            })
    }

    $phones = @()
    if (-not [string]::IsNullOrWhiteSpace($actionContext.Data.MobilePhone)) {
        $phones += @{
            value = "$($actionContext.Data.MobilePhone)"
            type  = 'mobile'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($actionContext.Data.WorkPhone)) {
        $phones += @{
            value = "$($actionContext.Data.WorkPhone)"
            type  = 'work'
        }
    }

    $relations = @()
    if ($actionContext.Configuration.SetPrimaryManagerOnCreate -eq $tue) {
        if (-not [string]::IsNullOrWhiteSpace($actionContext.Data.Manager)) {
            $relations = @(@{
                    type  = "manager"
                    value = "$($actionContext.Data.Manager)"
                })
        }
    }

    if ([string]::IsNullOrWhiteSpace($actionContext.Configuration.InitialContainer)) {
        $orgUnitPath = ($actionContext.Data.Container)
    }
    else {
        $orgUnitPath = $actionContext.Configuration.InitialContainer
    }

    $account = [PSCustomObject]@{
        changePasswordAtNextLogin  = [System.Convert]::ToBoolean($actionContext.Data.ChangePasswordAtNextLogin)
        externalIds                = @(@{
                value = "$($actionContext.Data.ExternalId)"
                type  = "organization"
            })
        hashFunction               = "SHA-1"
        includeInGlobalAddressList = [System.Convert]::ToBoolean($actionContext.Data.includeInGlobalAddressList)
        name                       = @{
            givenName  = $actionContext.Data.GivenName
            familyName = $actionContext.Data.FamilyName
        }
        organizations              = $organizations
        orgUnitPath                = $orgUnitPath
        password                   = $SHA1HashString
        phones                     = $phones
        primaryEmail               = $actionContext.Data.PrimaryEmail
        relations                  = $relations
        Suspended                  = $true

    }
    write-output $account
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
#endregion

try {
    # Initial Assignments
    $outputContext.AccountReference = 'Currently not available'

    Write-Information 'Getting JWT token'
    $splatGetGoogleWSTokenParams = @{
        Issuer                 = $actionContext.Configuration.Issuer
        Subject                = $actionContext.Configuration.Subject
        Scopes                 = @("https://www.googleapis.com/auth/admin.directory.user")
        P12CertificateBase64   = $actionContext.Configuration.P12CertificateBase64
        P12CertificatePassword = $actionContext.Configuration.P12CertificatePassword
    }
    $accessToken = Get-GoogleWSAccessToken @splatGetGoogleWSTokenParams

    Write-Information 'Setting authentication headers'
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "Bearer $($accessToken)")

    # Validate correlation configuration
    if ($actionContext.CorrelationConfiguration.Enabled) {
        $correlationField = $actionContext.CorrelationConfiguration.AccountField
        $correlationValue = $actionContext.CorrelationConfiguration.PersonFieldValue

        if ([string]::IsNullOrEmpty($($correlationField))) {
            throw 'Correlation is enabled but not configured correctly'
        }
        if ([string]::IsNullOrEmpty($($correlationValue))) {
            throw 'Correlation is enabled but [accountFieldValue] is empty. Please make sure it is correctly mapped'
        }

        # Determine if a user needs to be [created] or [correlated]
        try {
            $query = "externalId:$correlationValue"
            $splatGetUserParams = @{
                Uri         = "https://www.googleapis.com/admin/directory/v1/users?query=$query&customer=my_customer"
                Method      = 'GET'
                Headers     = $headers
                ContentType = 'application/x-www-form-urlencoded'
            }
            $correlatedAccount = Invoke-RestMethod @splatGetUserParams
        }
        catch {
            if ($_.Exception.Response.StatusCode -ne 404) {
                throw
            }
        }
    }

    if (($null -ne $correlatedAccount) -and ($null -ne $correlatedAccount.users)) {
        if ($correlatedAccount.users.Count -eq 1) {
            $action = 'CorrelateAccount'
        }
        else {
            $action = 'MultipleFound'
        }
    }
    else {
        $action = 'CreateAccount'
    }

    # Process
    switch ($action) {
        'CreateAccount' {
            $account = New-GoogleAccountObject
            $splatCreateParams = @{
                Uri         = "https://www.googleapis.com/admin/directory/v1/users"
                Method      = 'POST'
                Body        = $account | ConvertTo-Json
                Headers     = $headers
                ContentType = 'application/json;charset=utf-8'
            }

            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information 'Creating and correlating GoogleWS account'
                $createdAccount = Invoke-RestMethod @splatCreateParams
                $outputContext.AccountReference = $createdAccount.id
                $auditLogMessage = "Create account was successful. AccountReference is: [$($outputContext.AccountReference)]. Account created in OU: [$($account.orgUnitPath)]"
            }
            else {
                $auditLogMessage = "[DryRun] Create and correlate GoogleWS account in OU: [$($account.orgUnitPath)], will be executed during enforcement"
            }
            break
        }

        'CorrelateAccount' {
            Write-Information 'Correlating GoogleWS account'
            $outputContext.Data = $correlatedAccount.users[0] | ConvertTo-HelloIDAccountObject
            $outputContext.AccountReference = $correlatedAccount.users[0].id
            $outputContext.AccountCorrelated = $true
            $auditLogMessage = "Correlated account: [$($outputContext.AccountReference)] on field: [$($correlationField)] with value: [$($correlationValue)]"
            break
        }

        'MultipleFound' {
            throw "Multiple accounts found for person where $correlationField is: [$correlationValue]"
        }
    }

    Write-Information $auditLogMessage
    $outputContext.success = $true
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Action  = $action
            Message = $auditLogMessage
            IsError = $false
        })
}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-GoogleWSError -ErrorObject $ex
        $auditMessage = "Could not create or correlate GoogleWS account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not create or correlate GoogleWS account. Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}