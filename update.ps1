#################################################
# HelloID-Conn-Prov-Target-GoogleWorkSpace-Update
# PowerShell V2
#################################################

# Remove BuildingId from actionContext.Data if empty (as we do not want to update it with an empty value)
if ([string]::IsNullOrEmpty($actionContext.Data.BuildingId)) {
    Write-Information "Skipping update of [BuildingId]. Reason: The provided value is empty. The current configuration does not allow setting this with an empty value."
    $actionContext.Data.PsObject.Properties.Remove("BuildingId")
}

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

function ConvertTo-HelloIDAccountObject {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $True)]
        [object]
        $GoogleAccountObject
    )

    process {
        # Extract location information from the Google Workspace user object
        # Locations represent physical spaces where the user works
        # Reference: https://developers.google.com/workspace/admin/directory/reference/rest/v1/users#Location
        # To extract additional location properties, add them alongside buildingId
        # Note: Currently supporting single location (selecting the first one from the locations array)
        # To support multiple locations, modify the retrieval logic to loop through all locations
        $buildingId = $null
        if ($null -ne $GoogleAccountObject.locations) {
            $location = $GoogleAccountObject.locations | Select-Object -First 1
            if (-not [string]::IsNullOrEmpty($location)) {
                $buildingId = $location.buildingId
            }
        }

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
            BuildingId                 = $buildingId
        }
        Write-Output $helloIdAccountObject
    }
}

function ConvertTo-GoogleAccountUpdateObject {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]
        $HelloIDAccountObject,

        [Parameter()]
        [object]
        $PropertiesToConvert,

        [Parameter()]
        [object]
        $PreviousGoogleAccountObject
    )

    process {
        $googleAccountUpdateObject = [PSCustomObject] @{}

        # Build the user's location information
        # Locations represent physical spaces where the user works (e.g., desk locations, buildings)
        # Reference: https://developers.google.com/workspace/admin/directory/reference/rest/v1/users#Location
        # Note: Currently supporting single location (selecting the first one during update)
        if (('BuildingId' -in $PropertiesToConvert.Name)) {
            [array]$locations = ($PreviousGoogleAccountObject.locations)

            if ($null -ne $PreviousGoogleAccountObject.locations) {
                $locations | Add-Member -MemberType 'NoteProperty' -Name 'buildingId' -Value "$($HelloIDAccountObject.BuildingId)" -Force
            }
            else {
                $locations = @{
                    type       = "desk"
                    area       = "desk"
                    buildingId = "$($HelloIDAccountObject.BuildingId)"
                }
            }
            $googleAccountUpdateObject | Add-Member -MemberType 'NoteProperty' -Name 'locations' -Value $locations -Force
        }

        if ('Container' -in $PropertiesToConvert.Name) {
            $googleAccountUpdateObject | Add-Member -MemberType 'NoteProperty' -Name 'orgUnitPath' -Value $HelloIDAccountObject.Container
        }

        if ('ExternalID' -in $PropertiesToConvert.Name) {
            $googleAccountUpdateObject | Add-Member -MemberType 'NoteProperty' -Name 'externalIds' -Value @(
                @{
                    value = "$($actionContext.Data.ExternalId)"
                    type  = 'organization'
                }
            )
        }

        if ('PrimaryEmail' -in $PropertiesToConvert.Name) {
            $googleAccountUpdateObject | Add-Member -MemberType 'NoteProperty' -Name 'primaryEmail' -Value $HelloIDAccountObject.primaryEmail
        }

        if ('IncludeInGlobalAddressList' -in $PropertiesToConvert.Name) {
            [bool]$includeInGlobalAddressList = [System.Convert]::ToBoolean($HelloIDAccountObject.includeInGlobalAddressList )
            $googleAccountUpdateObject | Add-Member -MemberType 'NoteProperty' -Name 'includeInGlobalAddressList' -Value $includeInGlobalAddressList
        }

        if ('Manager' -in $PropertiesToConvert.Name) {
            $googleAccountUpdateObject | Add-Member -MemberType 'NoteProperty' -Name 'relations' -Value @(
                @{
                    type  = 'manager'
                    value = "$($HelloIDAccountObject.Manager)"
                }
            )
        }

        # Update organization information (department and title) if changed
        # Preserves existing organization data while updating the modified fields
        if (('Department' -in $PropertiesToConvert.Name) -or ('Title' -in $PropertiesToConvert.Name)) {
            [array]$organizations = ($PreviousGoogleAccountObject.organizations)

            if ($null -ne $PreviousGoogleAccountObject.organizations) {
                $organizations | Add-Member -MemberType 'NoteProperty' -Name 'title' -Value "$($HelloIDAccountObject.Title)" -Force
                $organizations | Add-Member -MemberType 'NoteProperty' -Name 'department' -Value "$($HelloIDAccountObject.Department)" -Force
            }
            else {
                $organizations = @{
                    title      = "$($HelloIDAccountObject.Title)"
                    department = "$($HelloIDAccountObject.Department)"
                    type       = 'work'
                }
            }
            $googleAccountUpdateObject | Add-Member -MemberType 'NoteProperty' -Name 'organizations' -Value $organizations -Force
        }


        if (('FamilyName' -in $PropertiesToConvert.Name) -or ('GivenName' -in $PropertiesToConvert.Name)) {
            $name = @{
                givenName  = "$($HelloIDAccountObject.givenName)"
                familyName = "$($HelloIDAccountObject.FamilyName)"
            }
            $googleAccountUpdateObject | Add-Member -MemberType 'NoteProperty' -Name 'name' -Value $name
        }

        if (('MobilePhone' -in $PropertiesToConvert.Name) -or ('WorkPhone' -in $PropertiesToConvert.Name)) {
            [array]$phones = ($PreviousGoogleAccountObject.phones)
            $phoneTypes = @{
                MobilePhone = 'mobile'
                WorkPhone   = 'work'
            }

            # Update the phone numbers list by updating existing numbers, adding new ones, and removing any empty entries.
            foreach ($property in $phoneTypes.Keys) {
                if ($property -in $PropertiesToConvert.Name) {
                    $objectToUpdate = $phones | Where-Object { $_.type -eq ($property -split 'Phone')[0] }
                    if ($null -ne $objectToUpdate) {
                        if ([System.String]::IsNullOrEmpty($HelloIDAccountObject.$property)) {
                            $phones = $phones | Where-Object { $_.type -ne ($property -split 'Phone')[0] }
                        }
                        else {
                            $objectToUpdate.value = "$($HelloIDAccountObject.$property)"
                        }
                    }
                    else {
                        [array]$phones += ([PSCustomObject]@{
                                type  = $phoneTypes[$property]
                                value = "$($HelloIDAccountObject.$property)"
                            })
                    }
                }
            }
            $googleAccountUpdateObject | Add-Member -MemberType 'NoteProperty' -Name 'phones' -Value $phones
        }

        write-output $googleAccountUpdateObject
    }
}
#endregion

try {
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

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

    Write-Information 'Verifying if a GoogleWS account exists'
    try {
        $splatGetUserParams = @{
            Uri     = "https://www.googleapis.com/admin/directory/v1/users/$($actionContext.References.Account)"
            Method  = 'GET'
            Headers = $headers
        }
        $correlatedAccountGoogle = Invoke-RestMethod @splatGetUserParams
    }
    catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw $_
        }
    }

    $correlatedAccount = ConvertTo-HelloIDAccountObject -GoogleAccountObject $correlatedAccountGoogle
    $outputContext.PreviousData = $correlatedAccount

    # Always compare the account against the current account in target system
    if ($null -ne $correlatedAccount) {
        $splatCompareProperties = @{
            ReferenceObject  = @($correlatedAccount.PSObject.Properties)
            DifferenceObject = @($actionContext.Data.PSObject.Properties)
        }
        $propertiesChanged = Compare-Object @splatCompareProperties -PassThru | Where-Object { $_.SideIndicator -eq '=>' }
        
        if ($actionContext.Configuration.MoveAccountOnUpdate -eq $false) {
            [array]$propertiesChanged = $propertiesChanged | Where-Object { $_.Name -ne 'Container' }
            $outputContext.Data.Container = $actionContext.PreviousData.Container
        }
        if ($propertiesChanged) {
            $action = 'UpdateAccount'
        }
        else {
            $action = 'NoChanges'
        }
    }
    else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'UpdateAccount' {
            Write-Information "Account property(s) required to update: $($propertiesChanged.Name -join ', ')"
            $googleAccountUpdateObject = ConvertTo-GoogleAccountUpdateObject -HelloIDAccountObject $actionContext.Data -PropertiesToConvert $propertiesChanged -PreviousGoogleAccountObject $correlatedAccountGoogle

            Write-Information "Updating GoogleWS account with accountReference: [$($actionContext.References.Account)]"
            $splatUpdateParams = @{
                Uri         = "https://www.googleapis.com/admin/directory/v1/users/$($actionContext.References.Account)"
                # Use PUT instead of PATCH as Google API supports patch semantics, meaning that you only need to include the fields you wish to update. Fields that are not present in the request will be preserved, and fields set to null will be cleared.
                # Docs: https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/update 
                Method      = 'PUT'
                Body        = $googleAccountUpdateObject | ConvertTo-Json
                Headers     = $headers
                ContentType = 'application/json;charset=utf-8'
            }

            if (-not($actionContext.DryRun -eq $true)) {
                $updatedAccountGoogle = Invoke-RestMethod @splatUpdateParams
                $outputContext.Data = $updatedAccountGoogle | ConvertTo-HelloIDAccountObject
                if ($propertiesChanged.Name -contains 'primaryEmail') {
                    $outputContext.AccountReference = @{id = $correlatedAccountGoogle.id; primaryEmail = $updatedAccountGoogle.primaryEmail }
                }
            }
            else {
                Write-Information "[DryRun] Update GoogleWS account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Update account was successful, Account property(s) updated: [$($propertiesChanged.name -join ',')]"
                    IsError = $false
                })
            break
        }

        'NoChanges' {
            Write-Information "No changes to GoogleWS account with accountReference: [$($actionContext.References.Account)]"

            $outputContext.Data = $correlatedAccount

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = 'No changes will be made to the account during enforcement'
                    IsError = $false
                })
            break
        }

        'NotFound' {
            Write-Information "GoogleWS account: [$($actionContext.References.Account)] could not be found, possibly indicating that it may have been deleted"
            $outputContext.Success = $false
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "GoogleWS account with accountReference: [$($actionContext.References.Account)] could not be found, possibly indicating that it may have been deleted"
                    IsError = $true
                })
            break
        }
    }
}
catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-GoogleWSError -ErrorObject $ex
        $auditMessage = "Could not create or correlate GoogleWS account. Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not create or correlate GoogleWS account. Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }

    Write-Warning $warningMessage
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}