# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.2.1] - 2026-02-18

### Added
- Added correlate only scripting and fieldMapping
- Added permission for drives (permission, grant, revoke and subPermissions)
- Added resources for drives

## [1.2.0] - 2025-02-09

### Added
- Added `deleteAccount` configuration option to skip account deletion operations instead of permanently deleting accounts.
- Added support for building location information (`buildingId`) in user accounts, extractable from the `locations` field mapping.
- Added flexibility to specify Organizational Unit (OU) from either configuration settings (`InitialContainer`, `EnabledContainer`, `DisabledContainer`) or field mapping.
- Enhanced action context with `previousData` and `data` tracking for better change management and auditability.
- Import script now extracts and includes `buildingId` in the account object.

### Changed
- Updated configuration descriptions:
  - `DefaultDomain`: Now clarifies usage for resource creation and group sub-permissions.
  - `ParentOrgUnitPath`: Now clarifies usage for organizational unit resource creation.
- Improved character limit handling for `displayName` and `description` fields (max 100 characters).
- Moved logging statements outside of dry-run checks for better auditability.

### Fixed
- Improved handling of organizational unit changes during account updates.

## [1.1.1] - 2025-06-16

### Changed
- Fixed incorrect encoding in PowerShell 5.1 for `POST`/`PUT` requests.
- Fixed (phone) comparison logic.
- Fixed issues with updating mobile and work phone numbers.
- Fixed incorrect container changes when `MoveAccountOnUpdate` is enabled.
- Fixed potential type change when only one item remains in an array
- Updated ConvertTo-HelloIDAccountObject in Update, Create and Import script to be consistent.

## [1.1.0] - 2025-05-28

### Added
- Added Account Import script
- Added Group Permissions Import script
- Added Licenses Permissions Import script
- Added `Collection` parameter in function `Invoke-GoogleWSRestMethodWithPaging`

### Changed
- Bug Fix paging counter in `Invoke-GoogleWSRestMethodWithPaging`
- Bug Fix account object create/update script

## [1.0.0] - 2025-01-21

This is the first official release of _HelloID-Conn-Prov-Target-GoogleWorkSpace_. This release is based on template version _2.0.1_.

### Added

### Changed

### Deprecated

### Removed