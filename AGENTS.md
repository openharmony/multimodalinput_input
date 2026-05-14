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

Do not revert unrelated user changes in a dirty worktree. Prefer `rg` for search and keep edits narrowly scoped to existing module boundaries. Document non-obvious behavior in the closest design or test file.

## Multimodal Input Knowledge

Stable multimodal input background lives under `docs/knowledge/`. Before code changes in these areas, read the matching file:

| Area | Read first |
| --- | --- |
| Event flow: dispatch, target selection, hit testing, coordinates, synthetic events, cursor updates, high-frequency move/draw paths | `docs/knowledge/input-event-pipeline.md` |
| Display/window scope: display groups, focus isolation, capture/cancel/axis-end/redispatch, default-group fallback | `docs/knowledge/display-group-model.md` |
| Device scope: device/display binding, hotplug, virtual/remote devices, joystick/tablet/stylus/touchpad rules, lifecycle cleanup | `docs/knowledge/input-device-scope.md` |
| Context state: mouse/cursor caches, capture state, pointer sequences, keyboard focus reissue, UDS dispatch state, lazy allocation | `docs/knowledge/input-context-state.md` |
| Verification: build, board-side tests, PR evidence, rebuilt shared libraries, public API or configuration behavior | `docs/knowledge/board-verification.md` |

## Project-Specific Constraints

- Event dispatch and cursor rendering paths are high-frequency; do not add full-iteration scans, string formatting, or INFO logs in per-move or per-draw code.
- Keep device-category-specific ownership rules explicit instead of folding them into unrelated routing paths.
- Default-group state is valid for default initialization and legacy helper behavior. Non-default event chains should keep using their resolved context or sequence snapshot.
- Keep optional feature state lazy; do not allocate dispatch or rendering context state for ordinary default paths unless the code path requires it.
