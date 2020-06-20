# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- [[#166]] Add a method to restore the login with an access token.

### Changed

- [[#159]] Allow whitespace in HTTP headers in the HttpClient.
- [[42e70de]] Fix the creation of PresenceGetError responses.

[#166]: https://github.com/poljar/matrix-nio/pull/166
[#159]: https://github.com/poljar/matrix-nio/pull/159
[42e70de]: https://github.com/poljar/matrix-nio/commit/42e70dea945ae97b69b41d49cb57f64c3b6bd1c4

## 0.13.0 - 2020-06-05

### Added

- [[#145]] Added the `room_get_event()` method to `AsyncClient`.
- [[#151]] Added the `add_presence_callback` method to base `Client`.
- [[#151]] Added the `get_presence()` and `set_presence()` methods
  to `AsyncClient`.
- [[#151]] Added the `presence`, `last_active_ago`, `currently_active` and
  `status_msg` attributes to `MatrixUser`
- [[#152]] Added a docker container with E2E dependencies pre-installed.
- [[#153]] Added the `add_room_account_data_callback` method to base `Client`.
- [[#153]] Added the `fully_read_marker` and `tags` attributes to `MatrixRoom`.
- [[#156]] Added the `update_receipt_marker()` method to `AsyncClient`.
- [[#156]] Added the `unread_notifications` and `unread_highlights` attributes
  to `MatrixRoom`.

### Changed

- [[#141]] Improved the upload method to accept file objects directly.

[#141]: https://github.com/poljar/matrix-nio/pull/141
[#145]: https://github.com/poljar/matrix-nio/pull/145
[#151]: https://github.com/poljar/matrix-nio/pull/151
[#152]: https://github.com/poljar/matrix-nio/pull/152
[#153]: https://github.com/poljar/matrix-nio/pull/153
[#156]: https://github.com/poljar/matrix-nio/pull/156

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
