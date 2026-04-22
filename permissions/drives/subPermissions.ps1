############################################################################
# HelloID-Conn-Prov-Target-GoogleWorkSpace-Permissions-Drives-SubPermissions
# PowerShell V2
############################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Script Mapping lookup values
$contractCorrelationField = 'externalID'

$scopes = @(
    "https://www.googleapis.com/auth/admin.directory.group"
    "https://www.googleapis.com/auth/admin.directory.user"
    "https://www.googleapis.com/auth/drive"
)


# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$currentPermissions = @{}
foreach ($permission in $actionContext.CurrentPermissions) {
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName
}

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

try {
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
        $principalEmail = $correlatedAccount.primaryEmail
    }
    catch {
        if ($_.Exception.Response.StatusCode -ne 404) {
            throw $_
        }
    }

    #region Define desired permissions
    $actionMessage = "calculating desired permission"

    Write-Information 'Retrieve GoogleWS drives'
    $splatGetGroups = @{
        Uri     = "https://www.googleapis.com/drive/v3/drives?useDomainAdminAccess=true"
        Method  = 'GET'
        Headers = $headers
    }
    $googleDrives = Invoke-GoogleWSRestMethodWithPaging @splatGetGroups -CollectionName 'drives'
    $googleDrives | Add-Member -MemberType NoteProperty -Name "externalID" -Value $null -Force
    foreach ($googleDrive in $googleDrives) {
        if ($googleDrive.name -match '\|') {
            $googleDrive.externalID = ($googleDrive.name -split '\|')[1].Trim()
        }
        else {
            $googleDrive.externalID = $googleDrive.name 
        }
    }
    $googleDrivesGrouped = $googleDrives | Select-Object id, name, externalID | Group-Object externalID -AsHashTable -AsString
    if ($null -eq $googleDrivesGrouped) {
        $googleDrivesGrouped = @{}
    }

    $desiredPermissions = @{}
    if (-Not($actionContext.Operation -eq "revoke")) {
        # Example: Contract Based Logic:
        foreach ($contract in $personContext.Person.Contracts) {

            Write-Information "Contract: $($contract.ExternalId). In condition: $($contract.Context.InConditions)"
            if ($contract.Context.InConditions -OR ($actionContext.DryRun -eq $true)) {        
                # Get group to use objectGuid to avoid name change issues
                $correlationField = $contractCorrelationField
                $correlationValue = $contract.CostCenter.Code

                $group = $null
                $group = $googleDrivesGrouped["$($correlationValue)"]

                if (($group | Measure-Object).count -eq 0) {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "No Group found where [$($correlationField)] = [$($correlationValue)]"
                            IsError = $true
                        })
                }
                elseif (($group | Measure-Object).count -gt 1) {
                    $outputContext.AuditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission"
                            Message = "Multiple Groups found where [$($correlationField)] = [$($correlationValue)]. Please correct this so the groups are unique."
                            IsError = $true
                        })
                }
                else {
                    # Add group to desired permissions with the id as key and the displayname as value (use id to avoid issues with name changes and for uniqueness)
                    $desiredPermissions["$($group.id)"] = $group.Name
                }
            }
        }
    }
    #endregion Define desired permissions

    Write-Warning ("Desired Permissions: {0}" -f ($desiredPermissions.Values | ConvertTo-Json))
    Write-Warning ("Existing Permissions: {0}" -f ($actionContext.CurrentPermissions.DisplayName | ConvertTo-Json))

    #region Compare current with desired permissions and revoke permissions
    $newCurrentPermissions = @{}
    foreach ($permission in $currentPermissions.GetEnumerator()) {    
        if (-Not $desiredPermissions.ContainsKey($permission.Value) -AND $permission.Name -ne "No permissions defined") {
            #region Revoke permission
            $actionMessage = "revoking group [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            #List permissions of drive (driveId will be used as fileId)
            $splatListPermissions = @{
                Uri     = "https://www.googleapis.com/drive/v3/files/$($permission.Name)/permissions?supportsAllDrives=true&useDomainAdminAccess=true&fields=$([System.Uri]::EscapeDataString('permissions(id,emailAddress,displayName,role,type)'))"
                Method  = 'GET'
                Headers = $headers
            }

            $response = Invoke-RestMethod @splatListPermissions
            $listedPermissions = @($response.permissions)

            #Search permission on emailAddress (case-insensitive)
            $target = $listedPermissions | Where-Object { $_.emailAddress -ieq $principalEmail } | Select-Object -First 1

            # Create permission revoke body
            $splatRevokeMember = @{
                Uri     = "https://www.googleapis.com/drive/v3/files/$($permission.Name)/permissions/$($target.id)?supportsAllDrives=true&useDomainAdminAccess=true"
                Method  = 'DELETE'
                Headers = $headers
            }
    
            if (-Not($actionContext.DryRun -eq $true)) {

                $null = Invoke-RestMethod @splatRevokeMember

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "RevokePermission"
                        Message = "Revoked drive [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
                $outputContext.Success = $true
            }
            else {
                Write-Warning "DryRun: Would revoke drive [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
            #endregion Revoke permission
        }
        else {
            $newCurrentPermissions[$permission.Name] = $permission.Name
        }
    }
    #endregion Compare current with desired permissions and revoke permissions

    #region Compare desired with current permissions and grant permissions
    foreach ($permission in $desiredPermissions.GetEnumerator()) {
        $outputContext.SubPermissions.Add([PSCustomObject]@{
                DisplayName = $permission.Value
                Reference   = [PSCustomObject]@{ Id = $permission.Name }
            })

        if (-Not $currentPermissions.ContainsKey($permission.Name)) {
            #region Grant permission
            $actionMessage = "granting drive [$($permission.Value)] with id [$($permission.Name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)"

            # Create permission body
            # Add Organizer (shared drive) 
            # Shared drives: supportsAllDrives=true
            $organizerBody = @{
                type         = "user"
                role         = "fileOrganizer"
                emailAddress = $($correlatedAccount.primaryEmail)
            } 

            $addOrganizerSplatParams = @{
                Uri         = "https://www.googleapis.com/drive/v3/files/$($permission.Name)/permissions?supportsAllDrives=true&useDomainAdminAccess=true&sendNotificationEmail=false"
                Headers     = $headers
                Method      = "POST"
                Body        = ($organizerBody | ConvertTo-Json -Depth 10)
                ContentType = "application/json; charset=utf-8"
                Verbose     = $false 
                ErrorAction = "Stop"
            }

            if (-Not($actionContext.DryRun -eq $true)) {

                $null = Invoke-RestMethod @addOrganizerSplatParams

                $outputContext.AuditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission"
                        Message = "Granted drive [$($permission.value)] with id [$($permission.name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
                        IsError = $false
                    })
                $outputContext.Success = $true
            }
            else {
                Write-Warning "DryRun: Would grant drive [$($permission.value)] with id [$($permission.name)] to account with AccountReference: $($actionContext.References.Account | ConvertTo-Json)."
            }
            #endregion Grant permission
        }    
    }
    #endregion Compare desired with current permissions and grant permissions
}
catch {
    $outputContext.Success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-GoogleWSError -ErrorObject $ex
        $auditMessage = "Error $actionMessage. Error: $($_.Exception.Message)"
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