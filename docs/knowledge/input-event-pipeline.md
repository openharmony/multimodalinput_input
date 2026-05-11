# Input Event Pipeline Knowledge

This document records stable background for the multimodal input event pipeline.
Task-specific specs and implementation notes remain under `docs/superpowers/`.

## Pipeline Stages

Input processing should keep these stages explicit:

1. Normalize raw device events.
2. Resolve the event context and target scope.
3. Select target windows, focus windows, or dispatch recipients.
4. Dispatch to consumers.
5. Update drawing, rendering, or reporting state.

Policy decisions should not be hidden in low-level parsing or transport code.
When a feature changes target selection, focus, coordinates, cursor state, or
dispatch scope, the context must be resolved before those reads or writes.

## Common Code Areas

Use these paths as starting anchors, then follow the local call chain before
editing:

- Raw device and transport handling: `service/libinput_adapter/`,
  `service/message_handle/`, and `frameworks/proxy/`.
- Event normalization: `service/key_event_normalize/`,
  `service/mouse_event_normalize/`, and `service/touch_event_normalize/`.
- Dispatch and subscriber delivery: `service/event_dispatch/`,
  `service/event_handler/`, `service/interceptor/`, `service/monitor/`, and
  `service/subscriber/`.
- Window targeting and pointer drawing: `service/window_manager/`.
- Public API and compatibility projections: `interfaces/`, `frameworks/native/`,
  `frameworks/napi/`, and `frameworks/ets/`.

When a patch crosses these areas, name the boundary it is changing. For example,
"normalize before target lookup" is different from "redispatch after target
lookup", and the tests should cover the exact boundary.

## Typical Call Chains

Use these as orientation only; verify the current branch before editing because
feature branches may add intermediate handlers.

| Flow | Typical anchors | Notes |
| --- | --- | --- |
| Device event to normalized event | `service/libinput_adapter/` -> `service/*_event_normalize/` | Keep device parsing separate from policy decisions. |
| Normalized pointer to target | `MouseEventNormalize` or touch transform -> `InputWindowsManager::UpdateTargetPointer` | Resolve display/group context before hit testing or cursor state updates. |
| Keyboard to focused target | key normalize/handler -> `InputWindowsManager::UpdateTarget` or `HandleKeyEventWindowId` | Use the focus of the resolved scope, not unrelated default state. |
| Targeted event to client | `EventDispatchHandler` -> monitor/interceptor/subscriber/window consumer | Preserve target info and dispatch order through UDS delivery. |
| Pointer draw update | target/coordinate update -> `PointerDrawingManager` or `CursorDrawingComponent` | Avoid per-move scans and formatting-heavy logging. |
| Generated end or cancel | sequence snapshot -> target update -> dispatch/drawing/reporting -> cleanup | Keep context until all end-event consumers finish. |

If a change cannot be described as one of these flows, write down the new flow in
the nearest spec or test so later work can preserve the boundary.

## Event Context

Some input features receive an API or transport identifier first, then need to
resolve it to a runtime event context before target lookup. That context may
include user, display group, display, window group, device capability, or active
sequence information.

After resolution, the event chain should use the same context for target lookup,
focus selection, cursor state, synthetic events, and dispatch state.

Do not resolve a context in one stage and then read default-group or global
state in a later stage unless the code is intentionally serving a legacy default
query. If an event starts from a display id, device id, window id, token, or
transport connection, treat that value as an input to context resolution rather
than as the final authority for target-sensitive state.

## Event Type Notes

- Pointer-class events commonly affect coordinates, display range, cursor
  state, capture, hit testing, sequence snapshots, and drawing notifications.
- Keyboard-class events commonly depend on the focus state of the resolved
  target scope and may need reissue or subscriber behavior to stay scoped.
- Touch, tablet, stylus, touchpad, joystick, remote, and virtual input paths can
  share event containers while still having different ownership rules. Check the
  device category before moving logic into a generic helper.
- Synthetic, cancel, redispatch, and axis-end events should reuse the resolved
  context or captured sequence state from the original chain.

## Forbidden Shortcuts

- Do not make low-level parsers choose windows, focus, or dispatch policy.
- Do not let a later dispatch or drawing stage recover scope from a different
  identifier than the one used for target selection.
- Do not add INFO logs, string formatting, or whole-map scans to pointer move,
  cursor draw, redispatch, or generated-end loops.
- Do not create optional context state for unbound/default events just to make a
  read path simpler.

## High-Frequency Path Rules

Event move and cursor drawing paths are high-frequency. Avoid:

- Full map scans per move or draw.
- String formatting in hot paths.
- INFO-level logs per move or draw.
- Repeated context creation for unbound events.

Default event paths should stay on the existing fast path unless an explicit
context operation needs additional state.

Before adding work to a move, draw, or redispatch loop, check whether the needed
context can be resolved once and carried forward. Prefer cached resolved context
or sequence snapshots over repeated map walks and formatting-heavy diagnostics.

## Test Mapping

- Normalization changes usually need the closest test in
  `service/*_event_normalize/test/`.
- Dispatch or event-handler changes usually need `EventDispatchTest`,
  `EventHandlerTest`, or the closest subscriber/interceptor/monitor test target.
- Window targeting, focus, coordinate, capture, redispatch, and drawing changes
  usually need `InputWindowsManager*`, `PointerDrawingManager*`,
  `CursorDrawingComponent*`, or `PointerDispatchEventCacheStandaloneTest`.
- Public API shape changes usually need `InputNativeTest` or matching NAPI/ETS
  coverage.

When the behavior depends on real display, window, graphics, or device state,
add board-side evidence as described in `board-verification.md`.
