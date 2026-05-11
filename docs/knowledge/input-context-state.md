# Input Context State Knowledge

This document records stable rules for input state caches that affect target
selection, dispatch, or rendering.

## Authoritative Key

Event state that can affect target, coordinates, focus, drawing, or dispatch
isolation should be keyed by the resolved runtime context, not by an incidental
identifier from an earlier processing stage.

Device identifiers, display identifiers, and group identifiers can be useful
inputs to context resolution or compatibility projections. The authoritative
cache key should match the isolation model of the behavior being cached.

## Key Selection Guide

Choose the narrowest key that still matches the isolation model:

- User/display-group context for focus, target, cursor, capture, display range,
  and group-isolated dispatch state.
- Device plus resolved context when state depends on both physical device
  identity and the target scope.
- Sequence snapshot when end, cancel, axis-end, redispatch, drawing, or
  notification work must finish in the same scope as the original event.
- Legacy default key only for default initialization, explicit default queries,
  or documented compatibility helpers.

Do not split one behavior across unrelated keys such as display id for reads and
group id for writes. That pattern usually creates cross-group leaks.

## State That Must Be Group-Aware

The following state often needs scoped caches when the system supports multiple
users, display groups, windows, devices, or active sequences:

- Mouse position and mouse location.
- Cursor display range and current display.
- Cursor visibility, style, size, and color.
- Mouse capture mode.
- Pointer sequence snapshots.
- Axis and generated end-event state.
- Keyboard focus and reissue state when focus is scope-dependent.
- UDS dispatch target state affected by focus or hit testing.

## Code Anchors

- Window, focus, hit testing, and capture state: `InputWindowsManager` in
  `service/window_manager/`.
- Pointer sequence dispatch state: `PointerDispatchEventCache`.
- Mouse position, cursor style, cursor range, and drawing state:
  `PointerDrawingManager`, `CursorDrawingComponent`, `PointerRenderer`, and
  `ScreenPointer`.
- Display binding helpers: `InputDisplayBindHelper`.
- Device-derived state: `service/device_manager/` and
  `service/mouse_event_normalize/`.

When adding a cache or changing a key, update the closest unit tests to cover two
independent scopes with different values. A single default-scope test is not
enough for scoped behavior.

## State Ownership Table

| State | Preferred key | Owner or anchor | Cleanup trigger |
| --- | --- | --- | --- |
| Mouse position/location | Resolved display group, plus display when coordinates are physical | `InputWindowsManager`, `PointerDrawingManager` | Display/group change, sequence end, service restart |
| Cursor display range/current display | Resolved display group and display layout | `PointerDrawingManager`, `ScreenPointer` | Display topology change, bind change |
| Cursor style/size/color/visibility | User plus resolved group/window where behavior is scoped | `PointerDrawingManager`, `CursorDrawingComponent` | User switch, window destruction, style reset |
| Mouse capture mode | Resolved group/window | `InputWindowsManager::SetMouseCaptureMode` | Capture release, window destruction, cancel |
| Pointer sequence snapshot | Sequence id or pointer id plus resolved context | `PointerDispatchEventCache` | End/cancel after dispatch, drawing, and reporting finish |
| Axis/generated end state | Original sequence snapshot | `InputWindowsManager`, `PointerDispatchEventCache` | Axis end processing complete |
| Keyboard focus/reissue | Resolved display group | `InputWindowsManager::UpdateTarget` | Focus transfer, group/window update |
| UDS dispatch target state | Resolved target/window context | `EventDispatchHandler`, `InputWindowsManager` | Dispatch completion, target invalidation |

## Lazy Allocation

Do not create optional context state during service construction or ordinary
default input handling. Context state should be created only when an event,
explicit context operation, or test setup requires it.

Read-only legacy queries should not implicitly create optional dispatch or
render contexts.

Prefer lookup APIs that can report "not found" for optional context state. If a
read path creates state as a side effect, tests should prove that behavior is
intentional and does not affect the ordinary default path.

## Forbidden Shortcuts

- Do not key writes by group id and reads by display id for the same behavior.
- Do not allocate optional scoped state in service construction only to simplify
  later lookups.
- Do not erase pointer sequence context before end/cancel dispatch, drawing, and
  reporting are complete.
- Do not let read-only dump or query paths mutate scoped caches unless the API
  explicitly documents that side effect.
- Do not prove scoped behavior only with a default-group test.

## Sequence Timing

Pointer sequence state should stay available until the end event has completed
the necessary target calculation, pointer item update, drawing or state refresh,
UDS dispatch attempt, and RS notification. Cleanup before those steps risks
mixing the end event with the wrong context.

## Cleanup Order

For sequence-based pointer behavior, keep the sequence context until all
target-sensitive consumers have completed:

1. Resolve or recover the sequence context.
2. Calculate target window and pointer item updates.
3. Refresh drawing or cursor state if needed.
4. Attempt UDS dispatch and related event delivery.
5. Notify rendering or reporting components.
6. Clear the sequence snapshot and optional scoped state that is no longer live.

Cancel, axis-end, redispatch, and synthetic end events should follow the same
ownership rule even when they are generated after the original input event.

## Test Mapping

Use `PointerDispatchEventCacheStandaloneTest` for sequence snapshot behavior,
`InputWindowsManager*` for focus/target/capture state, `PointerDrawingManager*`
and `CursorDrawingComponent*` for cursor and drawing state, and
`InputDisplayBindHelper*` for display binding caches. Tests should cover lazy
allocation, read-only queries, cleanup, and at least one non-default or
multi-scope case when the behavior is scoped.
