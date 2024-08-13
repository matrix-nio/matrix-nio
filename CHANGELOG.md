# Changelog

All notable changes to this project will be documented in this file.

## [0.25.0] - 2024-08-13

### Features
- [[#449]] Aggregated Event Relations + Threading + Threaded/Private Read Receipts
- [[#489]] Compliance with MSC2844. BREAKING CHANGE.
- [[#490]] Moved callback execution to separate methods.
- [[#499]] Add stop_sync_forever method, to gracefully exit sync_forever loop.

### Bug Fixes
- [[#471]] Changing room_messages to conform to MSC3567
- [[#482]] [[#483]] [[#486]] Spec-compliant bugfixes for joined_member, e2ee, RoomContext
- [[#495]] remove creator property from event
- [[#498]] Properly pass JSON content to DownloadResponse
- [[#508]] Add room_read_markers type hints

### Miscellaneous Tasks
- Tagged releases will automatically be published to PyPI
- Many dependency bumps

[#449]: https://github.com/matrix-nio/matrix-nio/pull/449
[#471]: https://github.com/matrix-nio/matrix-nio/pull/471
[#482]: https://github.com/matrix-nio/matrix-nio/pull/482
[#483]: https://github.com/matrix-nio/matrix-nio/pull/483
[#486]: https://github.com/matrix-nio/matrix-nio/pull/486
[#489]: https://github.com/matrix-nio/matrix-nio/pull/489
[#498]: https://github.com/matrix-nio/matrix-nio/pull/498
[#499]: https://github.com/matrix-nio/matrix-nio/pull/499
[#490]: https://github.com/matrix-nio/matrix-nio/pull/490
[#495]: https://github.com/matrix-nio/matrix-nio/pull/495
[#508]: https://github.com/matrix-nio/matrix-nio/pull/508


## [0.24.0] - 2024-01-18

### Miscellaneous Tasks

- [[#473]] Update pre-commit hooks, fix issues with sphinx-lint
- [[#472]] [[#475]] Add content to `built-with-nio`
- [[#468]] Bump `aiohttp` from 3.8.6 to 3.9.0
- [[#461]] Support `python3.12`
- [[#478]] Bump `pycryptodome` from 3.19.0 to 3.19.1

[#461]: https://github.com/poljar/matrix-nio/pull/461
[#468]: https://github.com/poljar/matrix-nio/pull/468
[#472]: https://github.com/poljar/matrix-nio/pull/472
[#473]: https://github.com/poljar/matrix-nio/pull/473
[#475]: https://github.com/poljar/matrix-nio/pull/475
[#478]: https://github.com/poljar/matrix-nio/pull/478

## [0.23.0] - 2023-11-17

### Bug Fixes

- [[#460]] Allow custom `ToDeviceEvent`s via `UnknownToDeviceEvent`
- [[#463]] Remove callback execution boilerplate + allow arbitrary callable/awaitable objects
- [[#457]] Fix schemas for `m.room.avatar` and `m.room.canonical_alias`
- [[#403]] Propagate `asyncio.CancelledError` in `sync_forever`

### Features

- [[#451]] Introduce the DM room account data (`m.direct`)

### Miscellaneous Tasks

- [[#458]] Update the `nio-bot` description
- [[#462]] Don't manually build `libolm` during tests + `pre-commit autoupdate`
- [[#464]] Bump `aiohttp` from 3.8.5 to 3.8.6

[#460]: https://github.com/poljar/matrix-nio/pull/460
[#458]: https://github.com/poljar/matrix-nio/pull/458
[#462]: https://github.com/poljar/matrix-nio/pull/462
[#451]: https://github.com/poljar/matrix-nio/pull/451
[#463]: https://github.com/poljar/matrix-nio/pull/463
[#464]: https://github.com/poljar/matrix-nio/pull/464
[#457]: https://github.com/poljar/matrix-nio/pull/457
[#403]: https://github.com/poljar/matrix-nio/pull/403


## [0.22.1] - 2023-10-9

### Bug Fixes
- [[#453]] Fix `ImportError` from when e2e is not installed

[#453]: https://github.com/poljar/matrix-nio/pull/453


## [0.22.0] - 2023-10-6

### Bug Fixes

- [[#434]] Fix space handling to account for Matrix spec ambiguities.

### Features

- [[#426]] Add a simple streamed response to download to files
- [[#436]] Add get space hierarchy capability
- [[#437]] Support for Token-Authenticated Registration
- [[#330]] Add `room_type` to `room_create` API function to allow for custom room types
- [[#351]] Add support for `m.reaction` events (Closes [[#174]])

### Miscellaneous Tasks

- [[#427]], [[#446]] Add `.readthedocs.yaml` v2 to support ReadTheDocs migration
- [[#440]] Remove `future` dependency
- [[#438]] Fix `jsonschema` deprecations
- [[#439]] Replace `cgi.parse_header()`
- [[#441]] Run `pre-commit autoupdate` to fix deprecation
- [[#442]] Introduce `ruff` as a `pre-commit` hook + run on whole codebase
- [[#445]] Update `pre-commit` hooks
- [[#447]] Replace ALL type comments with type hints
- [[#448]] Add `pyupgrade`, `async`, various `flake8`, `Perflint`, and more `ruff` linting rules

[#174]: https://github.com/poljar/matrix-nio/issues/174
[#434]: https://github.com/poljar/matrix-nio/pull/434
[#426]: https://github.com/poljar/matrix-nio/pull/426
[#436]: https://github.com/poljar/matrix-nio/pull/436
[#437]: https://github.com/poljar/matrix-nio/pull/437
[#330]: https://github.com/poljar/matrix-nio/pull/330
[#351]: https://github.com/poljar/matrix-nio/pull/351
[#427]: https://github.com/poljar/matrix-nio/pull/427
[#446]: https://github.com/poljar/matrix-nio/pull/446
[#440]: https://github.com/poljar/matrix-nio/pull/440
[#438]: https://github.com/poljar/matrix-nio/pull/438
[#439]: https://github.com/poljar/matrix-nio/pull/439
[#441]: https://github.com/poljar/matrix-nio/pull/441
[#442]: https://github.com/poljar/matrix-nio/pull/442
[#445]: https://github.com/poljar/matrix-nio/pull/445
[#447]: https://github.com/poljar/matrix-nio/pull/447
[#448]: https://github.com/poljar/matrix-nio/pull/448


## [0.21.2] - 2023-7-17

### Bug Fixes

- [[#423]] Revert [[#411]] due to backwards-incompatibilities.

[#423]: https://github.com/poljar/matrix-nio/pull/423

## [0.21.1] - 2023-7-16

### Bug Fixes

- [[#422]] `async_client.whoami` will alter the state of `async_client` correctly, and accept all spec-compliant fields.

### Miscellaneous Tasks

- [[#420]] Add `python3.8` tests to workflow.

[#422]: https://github.com/poljar/matrix-nio/pull/422
[#420]: https://github.com/poljar/matrix-nio/pull/420

## [0.21.0] - 2023-7-14

### Breaking Changes

- [[#416]] Drop support for end-of-life `python3.7`
- [[#413]] Drop usage of `logbook` in favor of standard library `logging`
  - This fixes an issue where logging was effectively disabled by default.

### Features

- [[#409]] Support m.space.parent and m.space.child events
- [[#418]] Add ability to knock on a room, and enable knocking for a room

### Documentation

- Add documentation on how to configure `logging`
- Note in `README` that room upgrades/tombstone events *are* supported

### Miscellaneous Tasks

- [[#401]] Removing skip for passing test
- [[#417]] Add type hints
- [[#406]] [[#407]] [[#414]] Add content to `built-with-nio`

### Bug Fixes

- [[#408]] Properly generate code coverage
- [[#411]] Fixed bug in Event Callbacks

[#416]: https://github.com/poljar/matrix-nio/pull/416
[#413]: https://github.com/poljar/matrix-nio/pull/413
[#409]: https://github.com/poljar/matrix-nio/pull/409
[#418]: https://github.com/poljar/matrix-nio/pull/418
[#401]: https://github.com/poljar/matrix-nio/pull/401
[#417]: https://github.com/poljar/matrix-nio/pull/417
[#406]: https://github.com/poljar/matrix-nio/pull/406
[#407]: https://github.com/poljar/matrix-nio/pull/407
[#414]: https://github.com/poljar/matrix-nio/pull/414
[#408]: https://github.com/poljar/matrix-nio/pull/408
[#411]: https://github.com/poljar/matrix-nio/pull/411

## [0.20.2] - 2023-3-26

### Miscellaneous Tasks

- Upgrade dependencies
- Various test, formatting, type hinting fixes
- Update GitHub Workflow Actions versions for CI
- [[#384]] Add content to `built-with-nio`

### Bug Fixes

- [[#335]] Default to the configured request timeout when syncing
- [[#354]] Fix `first_sync_filter` parameter of `AsyncClient.sync_forever`
- [[#357]] Element exports keys without required fields
- [[#396]] Fix `timeline->limited` being required

[#384]: https://github.com/poljar/matrix-nio/pull/384
[#335]: https://github.com/poljar/matrix-nio/pull/335
[#354]: https://github.com/poljar/matrix-nio/pull/354
[#357]: https://github.com/poljar/matrix-nio/pull/357
[#396]: https://github.com/poljar/matrix-nio/pull/396

## [0.20.1] - 2022-11-09

### Bug Fixes

- Fix Python 3.11 compatibility

## [0.20.0] - 2022-09-28

### Bug Fixes

- Fix import sequence errors.
- Exclude `tests/data/` from pre-commit workflow.
- Only accept forwarded room keys from our own trusted devices

### Documentation

- Mention that room key backups are unsupported.
- Add matrix-webhook to built-with-nio
- Add matrix-asgi to built-with-nio

### Features

- Add `mxc` URI parameter to `AsyncClient.download` and deprecate `server_name` and `media_id`.

### Miscellaneous Tasks

- Remove the usage of the imp module
- Fix our import order
- Fix a bunch of typos
- Remove key re-sharing
- Remove some unnecessary test code
- Add poetry to the test requirements
- Style fixes
- Sort our imports

### Refactor

- Clean up and make a bunch of tests more consistent

### Styling

- Add config for `pre-commit`.
- Fix formatting using `black` and `isort`.
- Convert from `str.format` to f-strings.

### Testing

- Update test for `AsyncClient.download`.
- Fix our async tests

### Ci

- Add `black` and `isort`.

## 0.19.0 - 2022-02-04

- [[#296]] Allow creating spaces
- [[#293]] Add special check for "room_id" in PushEventMatch
- [[#291]] Send empty object with m.read receipt
- [[#288]] Update aiohttp-socks dependency
- [[#286]] Fix type annotation for async callbacks in add_event_callback
- [[#285]] Remove chain_index field when sending room keys
- [[#281]] Add support for room upgrades

[#296]: https://github.com/poljar/matrix-nio/pull/296
[#293]: https://github.com/poljar/matrix-nio/pull/293
[#291]: https://github.com/poljar/matrix-nio/pull/291
[#288]: https://github.com/poljar/matrix-nio/pull/288
[#286]: https://github.com/poljar/matrix-nio/pull/286
[#285]: https://github.com/poljar/matrix-nio/pull/285
[#281]: https://github.com/poljar/matrix-nio/pull/281

## 0.18.7 - 2021-09-27

- [[#277]] Allow setting custom headers with the client.
- [[#276]] Allow logging in using an email.
- [[#273]] Use the correct json format for login requests.

[#277]: https://github.com/poljar/matrix-nio/pull/277
[#276]: https://github.com/poljar/matrix-nio/pull/276
[#273]: https://github.com/poljar/matrix-nio/pull/273

## 0.18.6 - 2021-07-28

- [[#272]] Allow the mimetype to be in the info for encrypted images

[#272]: https://github.com/poljar/matrix-nio/pull/272

## 0.18.5 - 2021-07-26

- [[1f17a20]] Fix errors due to missing keys in syncs

[1f17a20]: https://github.com/poljar/matrix-nio/commit/1f17a20ca818c1c3a0c2e75fdc64da9c629eb5f9

## 0.18.4 - 2021-07-14

- [[#265]] Fix parsing syncs missing invite/join/leave rooms

[#265]: https://github.com/poljar/matrix-nio/pull/265

## 0.18.3 - 2021-06-21

- [[#264]] Allow for devices in keys query that have no signatures

[#264]: https://github.com/poljar/matrix-nio/pull/264

## 0.18.2 - 2021-06-03

- [[#261]] Use the IV as is when decrypting attachments
- [[#260]] Always load the crypto data, even if a new account was made

[#260]: https://github.com/poljar/matrix-nio/pull/260
[#261]: https://github.com/poljar/matrix-nio/pull/261

## 0.18.1 - 2021-05-07

- [[#258]] Fix sticker event parsing

[#258]: https://github.com/poljar/matrix-nio/pull/256

## 0.18.0 - 2021-05-06

- [[#256]] Upgrade our dependencies
- [[#255]] Relax the sync response json schema
- [[#253]] Support the BytesIO type for uploads
- [[#252]] Add a sticker events type

[#256]: https://github.com/poljar/matrix-nio/pull/256
[#255]: https://github.com/poljar/matrix-nio/pull/255
[#253]: https://github.com/poljar/matrix-nio/pull/253
[#252]: https://github.com/poljar/matrix-nio/pull/252

## 0.17.0 - 2021-03-01

- [[#228]] Add support for global account data
- [[#222]] Add support for push rules events and API
- [[#233]] Treat `device_lists` in `SyncResponse` as optional
- [[#239]] Add support for authenticated `/profile` requests
- [[#246]] Add support for SOCKS5 proxies

[#228]: https://github.com/poljar/matrix-nio/pull/228
[#222]: https://github.com/poljar/matrix-nio/pull/222
[#233]: https://github.com/poljar/matrix-nio/pull/233
[#239]: https://github.com/poljar/matrix-nio/pull/239
[#246]: https://github.com/poljar/matrix-nio/pull/246

## 0.16.0 - 2021-01-18

- [[#235]] Expose the whoami API endpoint in the AsyncClient.
- [[#233]] Treat device lists as optional in the Sync response class.
- [[#228]] Add support for account data in the AsyncClient.
- [[#223]] Percent encode user IDs when they appear in an URL.

[#235]: https://github.com/poljar/matrix-nio/pull/235
[#233]: https://github.com/poljar/matrix-nio/pull/233
[#228]: https://github.com/poljar/matrix-nio/pull/228
[#223]: https://github.com/poljar/matrix-nio/pull/223

## 0.15.2 - 2020-10-29

### Fixed

- [[#220]] Copy the unencrypted `m.relates_to` part of an encrypted event into the
  decrypted event.

[#220]: https://github.com/poljar/matrix-nio/pull/220

## 0.15.1 - 2020-08-28

### Fixed

- [[#216]] `AsyncClient.room_get_state_event()`: return a
  `RoomGetStateEventError` if the server returns a 404 error for the request
- [[ffc4228]] When fetching the full list of room members, discard the members
  we previously had that are absent from the full list
- [[c123e24]] `MatrixRoom.members_synced`: instead of depending on the
  potentially outdated room summary member count, become `True` when the
  full member list has been fetched for the room.

[#216]: https://github.com/poljar/matrix-nio/pull/216
[ffc4228]: https://github.com/poljar/matrix-nio/commit/ffc42287c22a1179a9be7d4e47555693417f715d
[c123e24]: https://github.com/poljar/matrix-nio/commit/c123e24c8df81c55d40973470b825e78fd2f92a2

## 0.15.0 - 2020-08-21

### Added

- [[#194]] Add server discovery info (.well-known API) support to AsyncClient
- [[#206]] Add support for uploading sync filters to AsyncClient
- New [examples] and documentation improvements

### Fixed

- [[#206]] Fix `AsyncClient.room_messages()` to not accept filter IDs, using
  one results in a server error
- [[4b6ea92]] Fix the `SqliteMemoryStore` constructor
- [[4654c7a]] Wait for current session sharing operation to finish before
  starting a new one
- [[fc9f5e3]] Fix `OverflowError` occurring in
  `AsyncClient.get_timeout_retry_wait_time()` after a thousand retries

[#194]: https://github.com/poljar/matrix-nio/pull/194
[#206]: https://github.com/poljar/matrix-nio/pull/206
[4b6ea92]: https://github.com/poljar/matrix-nio/commit/4b6ea92cb69e445bb39bbfd83948b40adb8a23a5
[4654c7a]: https://github.com/poljar/matrix-nio/commit/4654c7a1a7e39b496b107337977421aeb5953974
[fc9f5e3]: https://github.com/poljar/matrix-nio/commit/fc9f5e3eda25ad65936aeb95412a26af73cedf6a
[examples]: https://matrix-nio.readthedocs.io/en/latest/examples.html

## 0.14.1 - 2020-06-26

### Fixed

- [[238b6ad]] Fix the schema for the devices response.

[238b6ad]: https://github.com/poljar/matrix-nio/commit/238b6addaaa85b994552e00007638b0170c47c43

## 0.14.0 - 2020-06-21

### Added

- [[#166]] Add a method to restore the login with an access token.

### Changed

- [[#159]] Allow whitespace in HTTP headers in the HttpClient.
- [[42e70de]] Fix the creation of PresenceGetError responses.
- [[bf60bd1]] Split out the bulk of the key verification events into a common module.
- [[9a01396]] Don't require the presence dict to be in the sync response.


### Removed

- [[cc789f6]] Remove the PartialSyncResponse. This is a breaking change, but
  hopefully nobody used this.

[#166]: https://github.com/poljar/matrix-nio/pull/166
[#159]: https://github.com/poljar/matrix-nio/pull/159
[42e70de]: https://github.com/poljar/matrix-nio/commit/42e70dea945ae97b69b41d49cb57f64c3b6bd1c4
[cc789f6]: https://github.com/poljar/matrix-nio/commit/cc789f665063b38be5b4146855e5204e9bc5bdb6
[bf60bd1]: https://github.com/poljar/matrix-nio/commit/bf60bd19a15429dc03616b9be11c3a205768e5ad
[9a01396]: https://github.com/poljar/matrix-nio/commit/9a0139673329fb82abc59496025d78a34b419b77

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
