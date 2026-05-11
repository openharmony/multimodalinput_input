# Repository Guidelines

## Project Structure & Module Organization

This is the OpenHarmony multimodal input component at `foundation/multimodalinput/input`. Core server logic is in `service/`; client/proxy code is in `frameworks/proxy/`; JS/NAPI, ETS, and native APIs are in `frameworks/` and `interfaces/`. Shared helpers live in `common/` and `util/`. Runtime configuration is under `etc/`, `sa_profile/`, `multimodalinput.cfg`, and `mmi_uinput.rc`. Tests are colocated in module `test/` directories, with fuzz targets under `test/fuzztest/`.

## Build, Test, and Development Commands

Run build commands from the OpenHarmony source root, not this subdirectory.

```sh
./build.sh --product-name rk3568 --build-target input --ccache
```

Builds the input component for `rk3568`.

```sh
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 InputWindowsManagerTest
```

Incrementally builds one unit-test target after GN output exists.

```sh
hdc file send out/rk3568/tests/unittest/input/input/InputWindowsManagerTest <device-temp-dir>/
hdc shell "cd <device-temp-dir> && ./InputWindowsManagerTest"
```

Pushes and runs a board-side test binary.

## Coding Style & Naming Conventions

Most code is C++ built with GN. Follow nearby style: 4-space indentation, `CamelCase` types, `lowerCamelCase` functions and locals, and trailing `_` for member fields. Keep GN targets aligned with existing `BUILD.gn` files. Prefer existing macros and helpers such as `CHKPV`, `CHKPR`, `MMI_HILOG*`, `RET_OK`, and `RET_ERR`.

## Testing Guidelines

Unit tests use GoogleTest/HWTEST (`HWTEST_F`, `EXPECT_*`, `ASSERT_*`) through `ohos_unittest` targets. Name tests descriptively, commonly `Feature_Behavior_001`. Add or update the closest module test when changing service logic, API behavior, event dispatch, or configuration parsing. Keep tests deterministic and clean up singleton or global state touched during setup.

## Commit & Pull Request Guidelines

Recent history uses concise Conventional Commit prefixes such as `fix:`, `docs:`, and `test:`. Keep commits scoped to one logical change. PRs should summarize behavior, list affected modules, link related issues or design docs, and include build/test evidence. Include board-side results for input dispatch, device, or window-manager changes.

## Architecture Principles

Keep input processing stages explicit: normalize raw events, resolve targets, dispatch to consumers, then update drawing or rendering state. Avoid mixing policy decisions into low-level parsing or transport code. Prefer context objects over scattered global state, and allocate optional feature state lazily. Maintain clear ownership between `service/`, `frameworks/`, and `interfaces/`.

## Agent-Specific Instructions

Do not revert unrelated user changes in a dirty worktree. Prefer `grep` or `rg` for search and `Edit` for manual edits. Keep edits narrowly scoped, follow existing module boundaries, and document non-obvious behavior in the closest design or test file.

## Design Documentation

Design specs live under `docs/superpowers/`. Before implementing task-specific changes to input dispatch, pointer drawing, window management, or device routing, read the relevant spec and plan files. Task-specific architectural decisions should not be re-litigated without updating the specs.

## Multimodal Input Knowledge

Stable multimodal input background lives directly under `docs/knowledge/`.
Before changing input dispatch, pointer drawing, window management, focus state,
or display/device binding, read the relevant knowledge file first:

- `docs/knowledge/input-event-pipeline.md`: event normalization, context
  resolution, hit testing, focus or target selection, dispatch, coordinate
  conversion, synthetic events, cursor updates, or high-frequency move/draw
  paths.
- `docs/knowledge/display-group-model.md`: user, display group, physical
  display, window group, focus isolation, cross-display pointer movement,
  capture/cancel/axis-end/redispatch, or default-group fallback behavior.
- `docs/knowledge/input-device-scope.md`: device category rules, device/display
  binding, virtual or remote input, joystick/tablet/stylus/touchpad handling,
  lifecycle cleanup after device/display/user changes, or compatibility fields
  used near routing decisions.
- `docs/knowledge/input-context-state.md`: scoped caches for mouse position,
  cursor state, capture mode, pointer sequences, axis end state, keyboard focus
  reissue, UDS dispatch state, lazy allocation, or cleanup timing.
- `docs/knowledge/board-verification.md`: build, board-side test, or PR evidence
  for changes to dispatch, device binding, window management, pointer drawing,
  public API behavior, configuration parsing, or rebuilt shared libraries.

Keyword routing can help when the task description is short:

| Task words | Read first |
| --- | --- |
| dispatch, target, hit test, coordinate, synthetic, redispatch | `input-event-pipeline.md` |
| display group, multi-display, focus, capture, cancel, axis end | `display-group-model.md` |
| device id, bind, hotplug, virtual, remote, touchpad, tablet, stylus | `input-device-scope.md` |
| cache, mouse position, cursor state, sequence, cleanup, lazy allocation | `input-context-state.md` |
| board, hdc, ninja target, gtest, evidence, shared library | `board-verification.md` |

Use `docs/knowledge/` for durable architecture and workflow knowledge. Use `docs/superpowers/` for task-specific specs, plans, reports, and design alignment records.

## Project-Specific Constraints

- Event dispatch and cursor rendering paths are high-frequency; do not add full-iteration scans, string formatting, or INFO logs in per-move or per-draw code.
- Keep device-category-specific ownership rules explicit instead of folding them into unrelated routing paths.
- Default-group state is valid for default initialization and legacy helper behavior. Non-default event chains should keep using their resolved context or sequence snapshot.
- Keep optional feature state lazy; do not allocate dispatch or rendering context state for ordinary default paths unless the code path requires it.
