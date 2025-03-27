# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-03-28

### Added
- Production build process with code minification using Terser
- Custom minification script with size optimization reporting
- Source maps generation for debugging minified code
- License/copyright preservation in minified files
- Separate development and production build configurations
- New build scripts: `build:prod` and `build:all`
- Documentation for build and minification process

### Changed
- Updated TypeScript configuration for optimal production builds
- Improved package exports configuration
- Enhanced build pipeline with better error handling

## [2.0.1] - 2025-03-15

### Fixed
- Performance improvements for large role hierarchies
- Fixed edge case in permission caching

## [2.0.0] - 2025-02-28

### Added
- Complete rewrite with improved performance
- Advanced caching mechanisms
- Better TypeScript integration

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
