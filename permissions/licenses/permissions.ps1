##########################################################################
# HelloID-Conn-Prov-Target-GoogleWorkSpace-Permissions-License-Permissions
# PowerShell V2
##########################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

try {
    # For a complete overview of all available licenses, refer to: https://developers.google.com/admin-sdk/licensing/v1/how-tos/products
    $retrievedPermissions = @(
        @{
            name = 'Google Workspace Business Starter'
            id   = '1010020027'
        },
        @{
            name = 'Google Workspace Business Standard'
            id   = '1010020028'
        },
        @{
            name = 'Google Workspace Business Plus'
            id   = '1010020025'
        },
        @{
            name = 'Google Workspace Enterprise Essentials'
            id   = '1010060003'
        },
        @{
            name = 'Google Workspace Enterprise Starter'
            id   = '1010020029'
        },
        @{
            name = 'Google Workspace Enterprise Standard'
            id   = '1010020026'
        },
        @{
            name = 'Google Workspace Enterprise Plus (formerly G Suite Enterprise)'
            id   = '1010020020'
        },
        @{
            name = 'Google Workspace Essentials (formerly G Suite Essentials)'
            id   = '1010060001'
        },
        @{
            name = 'Google Workspace Enterprise Essentials Plus'
            id   = '1010060005'
        },
        @{
            name = 'Google Workspace Frontline Starter'
            id   = '1010020030'
        },
        @{
            name = 'Google Workspace Frontline Standard'
            id   = '1010020031'
        }
    )

    foreach ($permission in $retrievedPermissions) {
        $outputContext.Permissions.Add(
            @{
                DisplayName    = $permission.name
                Identification = @{
                    Reference   = $permission.id
                    DisplayName = $permission.name
                }
            }
        )
    }
} catch {
    $ex = $PSItem
    Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
}
