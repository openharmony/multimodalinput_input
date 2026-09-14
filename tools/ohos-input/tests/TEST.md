# ohos-input unit tests

Tests use the OpenHarmony gtest framework (`HWTEST_F`) and follow the layout of
`ohos-pasteboard/tests`: one file per responsibility.

| File | Responsibility |
| --- | --- |
| `command_runner.h` | shared helpers: run `ExecuteCommand` capturing stdout, parse JSON, compare recorded controller calls |
| `mock_controller_factory.h/.cpp` | link-time stubs for `InputManager`, `MouseControllerImpl` and `KeyboardControllerImpl` |
| `modifier_test.cpp` | `ParseModifiers` ordering, single keys, malformed and duplicate input |
| `option_parser_test.cpp` | `ParseOptionPairs` whitelist/duplicates, `ParseNumber` defaults, ranges and messages |
| `command_table_test.cpp` | read-only command lookup, declaration order, stable repeated lookup |
| `printer_test.cpp` | JSON shape, help printing, parameter, unknown-command and controller-error mappings |
| `executor_test.cpp` | help routing (global/command, `--help` anywhere), `--version`, unknown command JSON, command availability |
| `mouse_support_test.cpp` | `ValidateScrollClicks` boundaries and `ParseButton` names/defaults |
| `mouse_drag_command_test.cpp` | `BuildDragSteps` step splitting, stationary and cross-display paths, no overflow |
| `integration_test.cpp` | full command execution against mock controllers: call order, validation before controller creation, failure paths and controller destruction |

## Host mock link boundary

`mock_controller_factory.cpp` supplies test-only definitions of `InputManager` creation/coordinate methods
and the platform Controller constructors, destructors and input methods. The test target uses the real
platform headers and production CLI sources; no mock subclasses or replacement headers
are used. `OhosInputCommandTest` includes every CLI production source except `src/main.cpp`.
Do not add the real platform implementation sources to these test targets: their method symbols
are intentionally replaced to record command ordering and inject failures. These tests do not verify
platform injection or destructor cleanup; those require platform/board tests.

## Device execution matrix

| Command example | Coverage | Permission | Prerequisite |
| --- | --- | --- | --- |
| `ohos-input --help` / `--version` | top-level help and version | None | None |
| `ohos-input mouse-click --x 0 --y 0 --displayId 0 --button left --holdDuration 50 --modifier ctrl\|shift` | defaults, ranges, modifiers | CONTROL_DEVICE | PC |
| `ohos-input mouse-double-click --x 100 --y 200 --button right --holdDuration 100 --clickInterval 250 --modifier alt` | all options and interval | CONTROL_DEVICE | PC |
| `ohos-input mouse-scroll --clicks 1` / `--clicks -100 --modifier ctrl` | positive/negative boundaries, modifiers | CONTROL_DEVICE | PC |
| `ohos-input mouse-move --displayId 1 --x 100 --y 200 --modifier meta` | all options | CONTROL_DEVICE | PC |
| `ohos-input mouse-drag --srcDisplayId 0 --srcX 0 --srcY 0 --dstDisplayId 1 --dstX 100 --dstY 200 --button middle --duration 16 --modifier shift` | all options | CONTROL_DEVICE | PC |
| `ohos-input key-press --key 2049 --holdDuration 0 --modifier ctrl\|shift` | all options and modifier order | CONTROL_DEVICE | PC |
| invalid/missing options; malformed or duplicate modifiers; `clicks=0`; primary key duplicated in modifiers | parameter error and exit 2 before controller creation | None | None |
