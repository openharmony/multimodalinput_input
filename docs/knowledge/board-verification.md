# Board Verification Knowledge

This document records stable board-side verification practices for multimodal
input changes.

## Build Location

Run OpenHarmony build commands from the OpenHarmony source root:

```sh
cd <openharmony-source-root>
```

Common incremental build command:

```sh
prebuilts/build-tools/linux-x86/bin/ninja -C out/rk3568 InputWindowsManagerTest
```

Build the service or related test targets when changes touch dispatch, window
management, pointer drawing, device binding, or public behavior.

## Choosing Targets

Pick the smallest target set that covers the changed behavior, then add a board
run when the behavior depends on real windows, displays, devices, graphics, or
service integration.

- Event dispatch or event handler: `EventDispatchTest`, `EventHandlerTest`,
  `InputEventHandlerTest`, subscriber/interceptor/monitor targets as relevant.
- Window targeting, focus, capture, redispatch, cancel, or axis-end:
  `InputWindowsManagerTest`, `InputWindowsManagerEXTest`,
  `InputWindowsManagerCoverageTest`, or `InputWindowsManagerOneTest`.
- Display/device binding: `InputDisplayBindHelperTest`,
  `InputDisplayBindHelperBranchStandaloneTest`, `DeviceManagerTest`,
  `DeviceManagerExTest`, `InputDeviceManagerTestWithMock`, or
  `DeviceStateManagerTest`.
- Pointer drawing, cursor rendering, and sequence cache:
  `PointerDrawingManagerTest`, `PointerDrawingManagerExTest`,
  `PointerDrawingManagerSupTest`, `PointerDrawingManagerHardCursorTest`,
  `CursorDrawingComponentTest`, `CursorDrawingComponentCoverageTest`, or
  `PointerDispatchEventCacheStandaloneTest`.
- Mouse, touch, touchpad, tablet, and remote transforms: the closest
  `MouseEventNormalize*`, `TouchEventNormalize*`, `Touchpad*`,
  `TabletToolTransformTest`, or `RemoteControlTransformProcessorTestWithMock`
  target.
- Native API compatibility: `InputNativeTest` or `InputNativeHotkeyTest`.

## When Board Evidence Is Required

Board evidence is expected when a change affects any behavior that depends on
the real service, display server, input device stack, graphics surface, or UDS
delivery path. Unit-only evidence is usually enough for pure parser, helper, or
API argument validation changes that do not cross those boundaries.

| Change type | Minimum evidence |
| --- | --- |
| Dispatch, focus, target, capture, redispatch | Build and run the closest window/dispatch target; add board run when UDS or real windows are involved. |
| Pointer drawing or cursor rendering | Build drawing targets and run on board when surface, RS, hard cursor, or screen state is involved. |
| Device binding or hotplug | Build device/binding targets; run on board when physical device or display topology is required. |
| Public API compatibility | Build and run API tests; add board evidence if the API reaches service state. |
| Config parsing only | Build and run parser or closest unit target unless behavior changes at runtime. |

## Board Test Flow

Use `hdc` to push the target test binary and any locally rebuilt shared
libraries it needs. Run tests from a temporary board directory with
`LD_LIBRARY_PATH` pointing at that directory before system and vendor library
paths.

Example shape:

```sh
hdc file send out/rk3568/tests/unittest/input/input/InputWindowsManagerTest <device-temp-dir>/
hdc shell "cd <device-temp-dir> && LD_LIBRARY_PATH=<device-temp-dir>:/system/lib:/vendor/lib ./InputWindowsManagerTest"
```

If a unit test links against locally rebuilt service libraries, push those
libraries beside the test binary and put the temporary directory first in
`LD_LIBRARY_PATH`. If the test depends on system graphics, window manager, or
input service state, record the board image, product, and any setup commands
needed to reproduce the run.

## Common Environment Failures

Do not hide environment failures as passing tests. Call them out separately when
they are unrelated to the behavior under review:

- `hdc` connection or device authorization failure.
- Missing test binary or shared library on the board.
- `LD_LIBRARY_PATH` points to system libraries before rebuilt libraries.
- Graphics, surface, or window creation failure in pointer drawing tests.
- Permission, SELinux, or service-start failure before the tested code runs.
- GTest filter matches no tests.

## Evidence To Record

For PRs that affect input dispatch, device binding, window manager, or pointer
drawing, record:

- Build target names and result.
- Board device identifier if relevant.
- Exact test binary and gtest filter.
- Passed and failed test counts.
- Known environment failures, especially graphics or surface failures in pointer
  drawing tests.

Do not report a test as passed unless the command completed and the relevant
output was checked.

## Evidence Anti-Patterns

- Reporting a test as passed because the binary launched but the gtest summary
  was not checked.
- Omitting the gtest filter when only a subset was run.
- Reusing an old board result after changing code or rebuilt libraries.
- Forgetting to push rebuilt shared libraries for service-linked unit tests.
- Treating graphics, surface, permission, or `hdc` failures as behavior success.
- Listing only "built input" when the actual changed unit target was not built.

## PR Evidence Template

Use this shape in PR notes when board-side verification is required:

```text
Build:
- product: rk3568
- targets: <target names>
- result: <passed/failed, command checked>

Board:
- device/image: <identifier if relevant>
- pushed files: <test binary and rebuilt libraries>
- command: <exact hdc shell command or gtest filter>
- result: <passed/failed counts>
- environment notes: <none or known setup/environment issue>
```
