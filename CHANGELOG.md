# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Added

### Changed

- `Corestore` uses a `std::sync::RwLock` instead of `tokio::sync::RwLock`. Nothing holds it while a core is being created.
- `Corestore::verifying_key_from_discovery_key` is no longer `async`.

### Fixed

- Opening the same new core from two places at once could create it twice. Concurrent opens now share one creation, and a failed open can be retried.
- A core opened after `Corestore::replicate` could fail to attach to that connection, so it never replicated over it.

### Removed

<!-- next-url -->
[Unreleased]: https://github.com/cowlicks/corestore/compare/v0.1.0...HEAD
