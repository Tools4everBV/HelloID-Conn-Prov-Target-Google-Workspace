# HelloID-Conn-Prov-Target-GoogleWorkSpace

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://www.tools4ever.nl/connector-logos/googleworkspace-logo.png">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-GoogleWorkSpace](#helloid-conn-prov-target-googleworkspace)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
      - [Creating the Base64 Key from the `PKCS #12` Certificate](#creating-the-base64-key-from-the-pkcs-12-certificate)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Available lifecycle actions](#available-lifecycle-actions)
    - [Field mapping](#field-mapping)
  - [Remarks](#remarks)
    - [Uniqueness check](#uniqueness-check)
    - [Create lifecycle action](#create-lifecycle-action)
    - [Update lifecycle action](#update-lifecycle-action)
    - [Enable/Disable lifecyle actions](#enabledisable-lifecyle-actions)
    - [Delete lifecycle action](#delete-lifecycle-action)
    - [Permissions - groups](#permissions---groups)
      - [Static permissions](#static-permissions)
      - [Dynamic permissions](#dynamic-permissions)
    - [Permissions - Licenses](#permissions---licenses)
    - [Resources - Groups](#resources---groups)
    - [Resources - Organizational Units](#resources---organizational-units)
    - [Import - Account](#import---account)
    - [Import - Groups](#import---groups)
    - [Import - Licenses](#import---licenses)
  - [Development resources](#development-resources)
    - [API documentation](#api-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-GoogleWorkSpace_ is a _target_ connector. _GoogleWS_ provides a set of REST API's that allow you to programmatically interact with its data.

## Getting started

### Prerequisites

Before implementing this connector, ensure the following prerequisites are met:

- [ ] **Service Account**: Create a service account in Google Workspace. Visit: [Google Cloud Console - Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts).
- [ ] **Admin Account**: Have an admin account with permissions to manage users and groups within Google Workspace. Visit: [Google Admin Console - Users](https://admin.google.com/ac/users).
- [ ] **PKCS #12 Certificate**: Obtain and download a `PKCS #12` certificate for the service account.
- [ ] **Domain-Wide Delegation**: Enable domain-wide delegation to allow the service account to access Google Workspace APIs on behalf of users. The following API scopes are required:
  - [ ] [https://www.googleapis.com/auth/admin.directory.user](https://www.googleapis.com/auth/admin.directory.user)
  - [ ] [https://www.googleapis.com/auth/admin.directory.userschema](https://www.googleapis.com/auth/admin.directory.userschema)
  - [ ] [https://www.googleapis.com/auth/admin.directory.group](https://www.googleapis.com/auth/admin.directory.group)
  - [ ] [https://www.googleapis.com/auth/admin.directory.orgunit](https://www.googleapis.com/auth/admin.directory.orgunit)
  - [ ] [https://www.googleapis.com/auth/apps.licensing](https://www.googleapis.com/auth/apps.licensing)
- [ ] **Base64 Key**: Generate the base64-encoded key for the `PKCS #12` certificate.

#### Creating the Base64 Key from the `PKCS #12` Certificate

Use the following PowerShell script to create the base64-encoded key:

```powershell
$p12CertificatePath = 'C:\example\example.p12'
[System.Convert]::ToBase64String((Get-Content $p12CertificatePath -AsByteStream))
```

### Connection settings

The following settings are available:

| Setting                   | Description                                                                                                                                                                                                   | Mandatory | Example                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------ |
| Issuer                    | The client ID used to generate the token. Typically this is the service account ID used for authentication.                                                                                                   | Yes       | `example-service-account@project-id.iam.gserviceaccount.com` |
| Subject                   | The user or service account on whose behalf the token is issued. Typically represents the admin account that has been authorized to perform actions on behalf of users or manage the Google Workspace domain. | Yes       | `admin@example.com`                                          |
| P12CertificateBase64      | The Base64 encoded version of the P12 (PKCS #12) certificate. Refer to the readme for more information.                                                                                                       | Yes       | `MIIC... (truncated base64)`                                 |
| P12CertificatePassword    | The password used to protect the private key stored within the P12 (PKCS #12) certificate.                                                                                                                    | Yes       | `mypassword123`                                              |
| CustomerID                | The Customer ID of the Google Environment. Only required for Import Licenses script. It can be found in the Google Admin Console under `Account > Account Settings > Customer ID`.                            | Yes       | `C00000000`                                                  |
| InitialContainer          | The Organizational Unit in which accounts should be created. When not specified, the value is determined by the fieldMapping.                                                                                 | No        | `/Users/NewAccounts`                                         |
| EnabledContainer          | The Organizational Unit to which accounts should be moved when enabled. When not specified, the value is determined by the fieldMapping.                                                                      | No        | `/Users/EnabledAccounts`                                     |
| DisabledContainer         | The Organizational Unit to which accounts should be moved when disabled. When not specified, the value is determined by the fieldMapping.                                                                     | No        | `/Users/DisabledAccounts`                                    |
| MoveAccountOnUpdate       | Move account to a different container when the account update action is performed. The container is determined by the fieldMapping. The default value is set to `false`.                                      | No        | `true`                                                       |
| SetPrimaryManagerOnCreate | Set primary manager when an account is created. The default value is set to `false`.                                                                                                                          | No        | `true`                                                       |
| DefaultDomain             | The primary domain that is automatically assigned when you set up a Google Workspace environment. See: https://admin.google.com/ac/domains/manage?hl=en                                                       | No        | `example.com`                                                |
| ParentOrgUnitPath         | The organizational unit path under which new organizational units will be created. Use '/' for top-level OUs or specify an existing path (e.g., '/ParentContainer').                                          | No        | `/ParentContainer`                                           |

> [!NOTE]
> The configuration of the _Google Workspace_ connector is similar to the _Active Directory_ connector.

### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _GoogleWS_ to a person in _HelloID_.

| Setting                   | Value                             |
| ------------------------- | --------------------------------- |
| Enable correlation        | `True`                            |
| Person correlation field  | `PersonContext.Person.ExternalId` |
| Account correlation field | `ExternalID`                  |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Available lifecycle actions

The following lifecycle actions are available:

| Action                                      | Description                                                                                                   |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| create.ps1                                  | Creates a new account.                                                                                        |
| delete.ps1                                  | Removes an existing account.                                                                                  |
| disable.ps1                                 | Disables an account, preventing access without permanent removal.                                             |
| enable.ps1                                  | Enables an account, granting access.                                                                          |
| update.ps1                                  | Updates the attributes of an account.                                                                         |
| permissions/groups/grantPermission.ps1      | Grants specific groups to an account.                                                                         |
| permissions/groups/revokePermission.ps1     | Revokes specific groups from an account.                                                                      |
| permissions/groups/permissions.ps1          | Retrieves all available groups.                                                                               |
| permissions/licenses/grantPermission.ps1    | Grants specific licenses to an account.                                                                       |
| permissions/licenses/revokePermission.ps1   | Revokes specific licenses from an account.                                                                    |
| permissions/licenses/permissions.ps1        | Retrieves all available licenses.                                                                             |
| resources/groups/resources.ps1              | Creates groups.                                                                                               |
| resources/organizationalUnits/resources.ps1 | Creates organizational units.                                                                                 |
| configuration.json                          | Contains the connection settings and general configuration for the connector.                                 |
| fieldMapping.json                           | Defines mappings between person fields and target system person account fields.                               |
| uniquenessCheck.ps1                         | Validates the uniqueness of the `PrimaryEmail` in Google Workspace, including aliases and non-primary emails. |

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

## Remarks

The _Google Workspace_ connector has been developed to be functionally the same as the Active Directory target connector.

### Uniqueness check

The script validates the uniqueness of the `PrimaryEmail` in Google Workspace, including aliases and non-primary emails.

### Create lifecycle action

- __Manager__<br>
If the configuration setting `SetPrimaryManagerOnCreate` is enabled, the primary manager will be assigned when an account is created.

- __Container__<br>
If the configuration setting `InitialContainer` is assigned a value, that value will determine the container in which the user resides. If this setting is left empty, the value from `actionContext.Data.Container` will be used to determine the user's container.

- __Password__<br>
New accounts require a password. This password will be generated within the _create_ lifecycle action.

### Update lifecycle action

- __Container__<br>
The container is the location where the account will reside.

> [!IMPORTANT]
> - If the configuration setting `InitialContainer` is used, during the _create_ lifecycle action, the account will be created in the organizational unit specified for this setting.
> - If the configuration setting `InitialContainer` is empty, during the _create_ lifecycle action, the account will be created in the organizational unit specified in `actionContext.Data.Container`.
> - If the configuration setting `MoveAccountOnUpdate` is enabled, during the _update_ lifecycle action, the account will be moved to the container specified in `actionContext.Data.Container`.

- __Primary email address__<br>
The connector updates the primary email address as needed but does not remove any associated aliases. In case the primairy email address will be changed, the previous value will be automatically added as an alias.

- __Move Account on Update__<br>
If the configuration setting `moveAccountOnUpdate` is enabled, during the update lifecycle, the account will be moved to the location specified in the field _container_.

> [!NOTE]
While the API supports alias removal, this functionality is not implemented, as it is not a desired feature within the current scope.

> [!IMPORTANT]
The `primaryEmail` is also used in the _grant_ lifecycle action for license assignments. Therefore, it is stored within the _accountReference_ during the _create_ lifecycle action. The _accountReference_ will be updated during the _update_ lifecycle action in case the primary email has changed.

### Enable/Disable lifecyle actions

When an account is enabled or disabled, **and** if the configuration settings `EnabledContainer` or `DisabledContainer` are set, the account will be moved to the specified container **and** its status will be updated accordingly. If these settings are left empty, the account will be enabled or disabled in its current container.

### Delete lifecycle action

Within the _delete_ lifecycle action, the account will be deleted from _Google Workspace_.

### Permissions - groups

#### Static permissions

Static permissions include all permissions available in _Google Workspace_. These can be retrieved using the _/permissions/groups/permissions.ps1_ script.

#### Dynamic permissions

Dynamic permissions are groups created either by the resource script **or** by groups available in _Google Workspace_ with names corresponding to a contract property. Currently, this property is set to `department.DisplayName` within the _/permissions/groups/subPermissions.ps1_ script.

> [!NOTE]
Email address formatting is handled both in the resource script and within the dynamic permissions. Any changes to the formatting logic must be applied in both areas to maintain consistency.

### Permissions - Licenses

- __Fixed list of licenses__<br>
-
The _permissions_ script uses a predefined list of licenses.

> [!WARNING]
Please note that license assignment has not been fully tested due to their unavailability in the test environment.

### Resources - Groups

- __Email address generation__<br>
Email addresses are generated from the display name. Special characters, spaces, and double underscores are sanitized or replaced during this process.

> [!NOTE]
The system checks whether a group already exists based on the email address.

- __Default domain requirement__<br>
A default domain is required for the resource script. This domain is also utilized during lookups, ensuring consistent email formatting and identification. For more information on domains, please refer to the [configuration secttion.](#connection-settings)

- __Email uniqueness__<br>
Group email addresses must be unique across the system.

- __GroupName Non-uniqueness__<br>
Group names are not required to be unique, so additional validation or correlation logic may be necessary in certain cases.

> [!NOTE]
Email address formatting is handled both in the resource script and within the dynamic permissions. Any changes to the formatting logic must be applied in both areas to maintain consistency.

### Resources - Organizational Units

When creating organizational units (OUs) in Google Workspace, it is essential to define their hierarchy within the directory. Organizational units are structured in a tree format, with each OU having an optional parent. This structure allows for organized management of users, settings, and policies.

To create an organizational unit, you must specify key details such as:
- **`name`**: The display name of the organizational unit.
- **`orgUnitPath`**: The unique path representing the organizational unit within the hierarchy (e.g., `/Engineering/Development`).
- **`parentOrgUnitPath`**: The path of the parent container under which the new organizational unit will reside. This parameter is mandatory unless the organizational unit is being created at the root level. Use `/` as the value for `parentOrgUnitPath` to place the organizational unit at the top level.

> [!NOTE]
> The `parentOrgUnitPath` must be set within the [configuration.](#connection-settings)

### Import - Account
The import account script uses the same `ConvertTo-HelloIDAccountObject` function as the create and update scripts to map the Google account object to the HelloID field mapping. Keep in mind that any changes to the field mapping may also require updates to this function

### Import - Groups
Only the groups that contain members are shown in HelloID.

### Import - Licenses
- The licenses are static permissions in HelloID, so they cannot be retrieved from Google. Therefore, the list used in the permissions script is also used in the import script. Note that this static permission list should match exactly. The only difference between the lists is that the import script also requires a ProductID, which can be found in the Google API documentation. Currently, all the permissions listed are also included in the import script.

- Only the licenses that contain members are shown in HelloID.
- To retrieve the members of a `license (SKU)`, the API also requires a `CustomerId`, which can be configured in the connector settings.

## Development resources

### API documentation

The API documentation can be found using the links below.

| Endpoint                   | URL                                                                                             | Actions                                             |
| -------------------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| Validate account           | https://developers.google.com/admin-sdk/directory/v1/guides/manage-users#get_user               | All                                                 |
| Create account             | https://developers.google.com/admin-sdk/directory/v1/guides/manage-users#create_user            | Create                                              |
| Set manager                | https://developers.google.com/admin-sdk/directory/v1/guides/manage-users#user-relationships     | Create, Update                                      |
| Update account             | https://developers.google.com/admin-sdk/directory/v1/guides/manage-users#update_user            | Update, Enable, Disable                             |
| Delete account             | https://developers.google.com/admin-sdk/directory/v1/guides/manage-users#delete_user            | Delete                                              |
| Get groups                 | https://developers.google.com/admin-sdk/directory/v1/guides/manage-groups#get_all_domain_groups | Permissions\Groups\SubPermissions, Resources\Groups |
| Update group               | https://developers.google.com/admin-sdk/directory/v1/guides/manage-group-members                | Permissions\Groups\Grant, Permissions\Groups\Revoke |
| Create group               | https://developers.google.com/admin-sdk/directory/v1/guides/manage-groups                       | Resources\Groups                                    |
| Get lisenses               | https://developers.google.com/admin-sdk/licensing/v1/how-tos/products                           | Permissions\Licenses\Permissions                    |
| Add license                | https://developers.google.com/admin-sdk/licensing/reference/rest/v1/licenseAssignments/insert   | Permissions\Licenses\Grant                          |
| Remove license             | https://developers.google.com/admin-sdk/licensing/reference/rest/v1/licenseAssignments/delete   | Permissions\Licenses\Revoke                         |
| Get organizational unit    | https://developers.google.com/admin-sdk/directory/v1/guides/manage-org-units                    | Resources\OrganizationalUnits                       |
| Create organizational unit | https://developers.google.com/admin-sdk/directory/v1/guides/manage-org-units                    | Resources\OrganizationalUnits                       |

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
