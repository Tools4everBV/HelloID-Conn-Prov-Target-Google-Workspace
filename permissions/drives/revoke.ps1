############################################################################
# HelloID-Conn-Prov-Target-GoogleWorkSpace-Permissions-Drives-Revoke
# PowerShell V2
############################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

$scopes = @(
    "https://www.googleapis.com/auth/admin.directory.group"
    "https://www.googleapis.com/auth/admin.directory.user"
    "https://www.googleapis.com/auth/drive"
)

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

function Remove-StringLatinCharacters {
    param(
        [string]$String
    )
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding('Cyrillic').GetBytes($String))
}
#endregion functions

try{
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

    Write-Information 'Getting JWT token'
    $splatGetGoogleWSTokenParams = @{
        Issuer                 = $actionContext.Configuration.Issuer
        Subject                = $actionContext.Configuration.Subject
        Scopes                 = $scopes
        P12CertificateBase64   = $actionContext.Configuration.P12CertificateBase64
        P12CertificatePassword = $actionContext.Configuration.P12CertificatePassword
    }
    $accessToken = Get-GoogleWSAccessToken @splatGetGoogleWSTokenParams

    Write-Information 'Setting authentication headers'
    $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
    $headers.Add('Authorization', "Bearer $($accessToken)")

    Write-Information 'Verifying if a GoogleWS account exists'
    $splatGetUserParams = @{
        Uri     = "https://www.googleapis.com/admin/directory/v1/users/$($actionContext.References.Account)"
        Method  = 'GET'
        Headers = $headers
    }
    try {
        $correlatedAccount = Invoke-RestMethod @splatGetUserParams
    }
    catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw $_
        }
    }

    if ($null -ne $correlatedAccount) {
        $action = 'RevokePermission'
    }
    else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'RevokePermission' {
            Write-Information 'List permissions of drive'
            #List permissions of drive (driveId will be used as fileId)
            $splatListPermissions = @{
                Uri     = "https://www.googleapis.com/drive/v3/files/$($actionContext.References.Permission.Reference)/permissions?supportsAllDrives=true&useDomainAdminAccess=true&fields=$([System.Uri]::EscapeDataString('permissions(id,emailAddress,displayName,role,type)'))"
                Method  = 'GET'
                Headers = $headers
            }

            $response = Invoke-RestMethod @splatListPermissions
            $listedPermissions = @($response.permissions)

            #Search permission on emailAddress (case-insensitive)
            $target = $listedPermissions | Where-Object { $_.emailAddress -ieq $correlatedAccount.primaryEmail } | Select-Object -First 1

            # Create permission revoke body
            $splatRevokeMember = @{
                Uri     = "https://www.googleapis.com/drive/v3/files/$($actionContext.References.Permission.Reference)/permissions/$($target.id)?supportsAllDrives=true&useDomainAdminAccess=true"
                Method  = 'DELETE'
                Headers = $headers
            }



            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Revoking GoogleWS drive permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Reference)]"
                try {
                    $null = Invoke-RestMethod @splatRevokeMember
                }
                catch {
                    if (-not ($_.Exception.StatusCode -eq 409)) {
                        throw
                    }
                }

            }
            else {
                Write-Information "[DryRun] Revoke GoogleWS drive permission: [$($actionContext.PermissionDisplayName)] - [$($actionContext.References.Permission.Reference)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Revoke permission [$($actionContext.PermissionDisplayName)] was successful"
                    IsError = $false
                })
        }

        'NotFound' {
            Write-Information "GoogleWS account: [$($actionContext.References.Account)] could not be found, possibly indicating that it may have been deleted"
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "GoogleWS account: [$($actionContext.References.Account)] could not be found, possibly indicating that it may have been deleted"
                    IsError = $false
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
        $auditMessage = "Could not manage GoogleWS permissions. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Could not manage GoogleWS permissions. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}