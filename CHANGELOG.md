# Changelog

All notable changes to this project will be documented in this file.

* Each RDK Service has a CHANGELOG file that contains all changes done so far. When version is updated, add a entry in the CHANGELOG.md at the top with user friendly information on what was changed with the new version. Please don't mention JIRA tickets in CHANGELOG. 

* Please Add entry in the CHANGELOG for each version change and indicate the type of change with these labels:
    * **Added** for new features.
    * **Changed** for changes in existing functionality.
    * **Deprecated** for soon-to-be removed features.
    * **Removed** for now removed features.
    * **Fixed** for any bug fixes.
    * **Security** in case of vulnerabilities.

* Changes in CHANGELOG should be updated when commits are added to the main or release branches. There should be one CHANGELOG entry per JIRA Ticket. This is not enforced on sprint branches since there could be multiple changes for the same JIRA ticket during development. 

* In the future, generate this file by [`auto-changelog`](https://github.com/CookPete/auto-changelog).

## [1.0.6] - 2025-09-17

### Changed
- use version/branch from recipe (#19)

## [1.0.5] - 2025-05-16

### Changed
- Extend adpcm frame info


## [1.0.4] - 2025-03-31

### Changed
- Rationalize Voice Logging
- replace xraudio_keyword_phrase_t

### Fixed
- Unable to start new voice stream with conversational UI server


## [1.0.3] - 2025-02-07

### Added
- Add capability to remove array elements in json config combine script


## [1.0.2] - 2024-12-06

### Added
- Add KWD confidence score to VREX init message
