# CHANGELOG

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
Project **TRIES** adhering to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), however going through the active development stage and can't guarantee it (FOR NOW).


## [0.3.1] - 2025-05-19

## Changed
- `utils` feature flag is now passed down to `smart-account-auth` crate


## [0.3.0] - 2025-05-19

## Changed
- Stop exporting types individually and expose the whole `smart_account_auth` crate instead (under `types` feature flag)


## [0.2.1] - 2025-05-19

## Changed
- Session action and queries msgs & traits to top level export


## [0.2.0] - 2025-05-19

## Changed
- Re-exposing additional credential types from `smart-account-auth`


## [0.1.2] - 2025-05-19

## Changed
- Reusing `SessionInfo` from `smart-account-auth` insteading of defining a new local


## [0.1.1] - 2025-05-19

## Fixed
- Proto references to the wrong crate