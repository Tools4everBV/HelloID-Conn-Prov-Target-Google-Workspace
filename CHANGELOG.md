# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [2.0.0] - 22-04-2025
> [!WARNING]
> This change will update the permission reference in the HelloID Business Rules. As a result, HelloID will treat each permission as newly added, requiring you to reconfigure the permissions in the Business Rules.

### Changed
- Update the DisplayName in the permissions (licenses) grant and revoke script from `$actionContext.References.Permission.DisplayName` to `$actionContext.PermissionDisplayName`.
- Update the DisplayName in the permissions (groups) grant and revoke script from `$actionContext.References.Permission.DisplayName` to `$actionContext.PermissionDisplayName`.

### Removed
- Remove the 'Permissions DisplayName' from the Permissions reference.

## [1.0.0] - 21-01-2025

This is the first official release of _HelloID-Conn-Prov-Target-GoogleWorkSpace_. This release is based on template version _2.0.1_.

### Added

### Changed

### Deprecated

### Removed