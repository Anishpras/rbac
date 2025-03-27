# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2024-03-28

### Security
- Added robust input validation to prevent injection attacks
- Implemented circular reference detection in role hierarchies
- Enhanced default deny behavior to ensure security by default
- Added deep cloning of configuration objects to prevent mutation attacks
- Improved cache security with versioning and key sanitization
- Enhanced middleware to securely handle errors and default to access denial
- Added audit logging for security-critical operations
- Fixed race condition vulnerabilities during permission updates
- Improved error handling to avoid leaking sensitive information
- Made the userCan method safely handle null or invalid inputs
- Removed wildcard (*) permission from grantFullAccess and grantAll methods for stricter permission control

### Added
- Comprehensive security documentation and recommendations
- Security-focused test suite

### Changed
- Updated type definitions with better security guidance
- Improved validation in permission checking methods

## [1.1.0] - 2024-03-28

### Added
- Configured Biome for linting and formatting
- Improved typings for better TypeScript support

## [1.0.0] - 2024-03-28

### Added
- Initial release
- Core RBAC functionality including role-based permissions
- Role hierarchy support
- Express.js middleware integration
- Builder pattern for easy configuration
- Performance optimization with LRU caching
- Comprehensive type safety
