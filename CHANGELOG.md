# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.12.0 - 2020-05-21

### Added

- [[#140]] Added the `update_device()` method to the `AsyncClient`.
- [[#143]] Added the `login_info()` method to the `AsyncClient`.
- [[c4f460f]] Added support for the new SAS key agreement protocol.

### Fixed
- [[#146]] Fix room summary updates when new summary doesn't have any
  attributes.
- [[#147]] Added missing requirements to the test requirements file.

[#140]: https://github.com/poljar/matrix-nio/pull/140
[#143]: https://github.com/poljar/matrix-nio/pull/143
[#146]: https://github.com/poljar/matrix-nio/pull/146
[#147]: https://github.com/poljar/matrix-nio/pull/147
[c4f460f]: https://github.com/poljar/matrix-nio/commit/c4f460f62c9543a76eaf1dad4be8ff5ae9312243

## 0.11.2 - 2020-05-11

### Fixed

- Fixed support to run nio without python-olm.
- Fixed an incorrect raise in the group sessions sharing logic.
- Handle 429 errors correctly even if they don't contain a json response.

## 0.11.1 - 2020-05-10

### Fixed

- Fix a wrong assertion resulting in errors when trying to send a message.

## 0.11.0 - 2020-05-10

### Added
- Kick, ban, unban support to the AsyncClient.
- Read receipt sending support in the AsyncClient.
- Read receipt parsing and emitting.
- Support token login in the AsyncClient login method.
- Support for user registration in the BaseClient and AsyncClient.
- Support for ID based filters for the sync and room_messages methods.
- Support filter uploading.

### Changed
- Convert attrs classes to dataclasses.
- Fire the `synced` asyncio event only in the sync forever loop.

### Fixed
- Don't encrypt reactions.
- Properly put event relationships into the unencrypted content.
- Catch Too Many Requests errors more reliably.
- Better room name calculation, now using the room summary.

### Removed
- Removed the legacy store.
