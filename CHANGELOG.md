# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.1.1] - 16-06-2025

### Changed
- Fixed incorrect encoding in PowerShell 5.1 for `POST`/`PUT` requests.
- Fixed (phone) comparison logic.
- Fixed issues with updating mobile and work phone numbers.
- Fixed incorrect container changes when `MoveAccountOnUpdate` is enabled.
- Fixed potential type change when only one item remains in an array
- Updated ConvertTo-HelloIDAccountObject in Update, Create and Import script to be consistent.

## [1.1.0] - 28-05-2025

### Added
- Added Account Import script
- Added Group Permissions Import script
- Added Licenses Permissions Import script
- Added `Collection` parameter in function `Invoke-GoogleWSRestMethodWithPaging`

### Changed
- Bug Fix paging counter in `Invoke-GoogleWSRestMethodWithPaging`
- Bug Fix account object create/update script

## [1.0.0] - 21-01-2025

This is the first official release of _HelloID-Conn-Prov-Target-GoogleWorkSpace_. This release is based on template version _2.0.1_.

### Added

### Changed

### Deprecated

### Removed