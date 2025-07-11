# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-07-12

### Added

- Reduce lookup time by around 6x on first lookup on task (now it takes around 2s to decrypt + sync on first request on vault - around 6s total)
- Add variables cache for reducing lookup speed within the same task
- Add consistent lookup on temp directory, with session locking if the session is older than 30s
- Add warning message to clean sessions after run

### Fixed

- Avoid syncing on each lookup

## [1.0.0] - 2025-07-06

### Added

- Initial release of the `bitwarden_cli_wrapper` Ansible collection.
- Added lookup.py to retrieve secrets using `bw` CLI commands.
- Documentation in `README.md` for usage and setup.
