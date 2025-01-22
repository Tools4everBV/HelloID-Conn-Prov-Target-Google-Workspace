############################################################################
# HelloID-Conn-Prov-Target-GoogleWorkSpace-Permissions-Groups-SubPermissions
# PowerShell V2
############################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Script Configuration
$departmentLookupProperty = { $_.Department.DisplayName }

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
        $Headers
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
                if (-not ($null -eq $partialResult.nextPageToken)) {
                    $urlWithOffSetAndToken = $urlWithOffSet + "&pageToken=$($partialResult.nextPageToken)"
                } else {
                    $urlWithOffSetAndToken = $urlWithOffSet
                }

                $splatParams = @{
                    Uri         = $urlWithOffSetAndToken
                    Headers     = $Headers
                    Method      = $Method
                    ContentType = $ContentType
                }
                $partialResult = Invoke-RestMethod @splatParams -Verbose:$false

                if ($partialResult.groups.Count -gt 1) {
                    $returnList.AddRange($partialResult.groups)
                }

            } until ($null -eq $partialResult.nextPageToken)
            Write-Output $returnList -NoEnumerate
        } catch {
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
        Scopes                 = @('https://www.googleapis.com/auth/admin.directory.group', 'https://www.googleapis.com/auth/admin.directory.user')
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
        $null = Invoke-RestMethod @splatGetUserParams
    } catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw $_
        }
    }

    Write-Information 'Retrieve GoogleWS groups'
    $splatGetGroups = @{
        Uri     = "https://www.googleapis.com/admin/directory/v1/groups?customer=my_customer"
        Method  = 'GET'
        Headers = $headers
    }
    $googleGroups = Invoke-GoogleWSRestMethodWithPaging @splatGetGroups
    $googleGroupsGrouped = $googleGroups | Group-Object -Property email -AsHashTable -AsString
    if ($null -eq $googleGroupsGrouped) {
        $googleGroupsGrouped = @{}
    }

    # Collect current permissions
    $currentPermissions = [System.Collections.Generic.list[string]]::new()
    foreach ($permission in $actionContext.CurrentPermissions) {
        $currentPermissions.Add($permission.Reference.Id)
    }

    # Collect desired permissions
    $desiredPermissions = [System.Collections.Generic.list[string]]::new()
    if (-Not($actionContext.Operation -eq 'revoke')) {
        foreach ($contract in $personContext.Person.Contracts) {
            if ($contract.Context.InConditions -or $actionContext.DryRun) {
                $desiredPermissions.Add(($contract | Select-Object $departmentLookupProperty).$departmentLookupProperty)
            }
        }
    }

    # Process desired permissions to grant
    foreach ($permission in $desiredPermissions) {
        # Replace Spaces with underscore, # Remove Special Characters, except underscore, # Remove Double Underscores
        $permission = Remove-StringLatinCharacters -String $permission
        $emailFormatted = "$($permission -replace '\s', '_'  -replace '__', '_' )@$($actionContext.Configuration.DefaultDomain)"

        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = "$($permission) - $($emailFormatted)"
                Reference   = [PSCustomObject]@{
                    Id = $permission
                }
            })

        if ( -not ($permission -in $currentPermissions) ) {
            if (-Not($actionContext.DryRun -eq $true)) {
                $group = $googleGroupsGrouped["$($emailFormatted)"]

                if ($null -eq $group) {
                    throw "Group [$permission - $($emailFormatted)] does not exist in GoogleWS. Check the resource configuration and ensure the resource script creates the group correctly"
                } else {
                    $splatSetMember = @{
                        Uri         = "https://www.googleapis.com/admin/directory/v1/groups/$($group.id)/members"
                        Method      = 'POST'
                        Headers     = $headers
                        ContentType = 'application/json'
                        Body        = @{
                            id = "$($actionContext.References.Account)"
                        } | ConvertTo-Json
                    }
                    try {
                        $null = Invoke-RestMethod @splatSetMember
                    } catch {
                        # Member already exists
                        if (-not ($_.Exception.StatusCode -eq 409)) {
                            throw
                        }
                    }
                }

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = 'GrantPermission'
                        Message = "Granted access to group [$($permission) - $($emailFormatted)]"
                        IsError = $false
                    })
            }
        }
    }

    # Process current permissions to revoke
    foreach ($permission in $currentPermissions) {
        if ( -not ($permission -in $desiredPermissions) ) {
            if (-Not($actionContext.DryRun -eq $true)) {
                # Replace Spaces with underscore, # Remove Special Characters, except underscore, # Remove Double Underscores
                $permission = Remove-StringLatinCharacters -String $permission
                $emailFormatted = "$($permission -replace '\s', '_'  -replace '__', '_' )@$($actionContext.Configuration.DefaultDomain)"
                $group = $googleGroupsGrouped["$($emailFormatted)"]

                if ($null -eq $group) {
                    Write-Information "Group [$permission - $($emailFormatted)] does not exists in GoogleWS"
                } else {
                    $splatRevokeMember = @{
                        Uri     = "https://www.googleapis.com/admin/directory/v1/groups/$($group.id)/members/$($actionContext.References.Account)"
                        Method  = 'DELETE'
                        Headers = $headers
                    }
                    try {
                        $null = Invoke-RestMethod @splatRevokeMember
                    } catch {
                        if (-not ($_.ErrorDetails.Message -match 'Resource Not Found: memberKey.')) {
                            throw
                        }
                    }
                }
            }

            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Action  = 'RevokePermission'
                    Message = "Revoked access to group [$($permission) - $($emailFormatted)]"
                    IsError = $false
                })
        }
    }
    $outputContext.Success = $true
} catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-GoogleWSError -ErrorObject $ex
        $auditMessage = "Could not manage GoogleWS permissions. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    } else {
        $auditMessage = "Could not manage GoogleWS permissions. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditMessage
            IsError = $true
        })
}