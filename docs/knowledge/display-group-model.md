# Display Group Model Knowledge

OpenHarmony multimodal input runs across users, display groups, and windows.
This document records the stable model used when reasoning about input target
scope.

## User And Group Scope

The runtime environment can contain multiple user spaces. A user space can have
one or more foreground display groups. Each display group contains one or more
physical displays arranged as an extended screen group, and each group has its
own focus and window state.

Display groups are isolated for input. A pointer, keyboard, touchpad, stylus,
axis, joystick, or generated synthetic event that belongs to one display group
must not read or update another display group's target, focus, cursor, or
sequence state.

## Identity Model

Keep these identities distinct when reading code:

- User scope owns the active user space and can contain one or more foreground
  display groups.
- Display group scope owns focus, window state, cursor state, coordinate
  boundary, capture state, and active input sequences for a group of displays.
- Physical display scope identifies one screen inside a display group. It is not
  always enough to select a target-sensitive cache.
- Window group or window scope is selected after the event is associated with
  the owning user and display group.

If a function receives only a display id or window id, check where the owning
user and display group are resolved before it reads or writes target-sensitive
state.

## Scope Ownership Table

| State or decision | Expected owner | Do not use as sole authority |
| --- | --- | --- |
| Focus window and focus pid | Resolved display group | Physical display id alone |
| Pointer coordinate boundary | Resolved display group plus physical display layout | Last cursor display alone |
| Cursor visibility/style/range | Resolved display group, with user settings when applicable | Global singleton state |
| Mouse capture mode | Resolved display group/window scope | Default group after non-default target resolution |
| Pointer sequence target | Sequence snapshot from original resolved scope | Current default focus |
| Cancel, axis end, redispatch | Original resolved context or sequence snapshot | Recomputed default-group context |
| Device-display binding | Device plus owning display/group context | Device id alone |

## Device Targeting Scope

Input code should distinguish a physical display from the display group that
owns focus, window state, cursor state, and coordinate boundaries. A feature may
start from a display identifier, but target-sensitive logic often needs the
owning user and display group before selecting windows or updating state.

Pointer-class devices may need to move across displays that belong to the same
extended display group while staying inside that group's coordinate and window
scope. Keyboard-class paths should use the focus state of the resolved target
scope.

Device-specific configuration paths should remain separate when their ownership
rules differ from generic pointer or keyboard routing.

## Code Anchors

- Display and window targeting: `service/window_manager/`, especially
  `InputWindowsManager`, `InputDisplayBindHelper`, and
  `PointerDispatchEventCache`.
- Display lifecycle and display event monitoring:
  `service/display_state_manager/`.
- Pointer drawing and cursor state: `PointerDrawingManager`,
  `CursorDrawingComponent`, `PointerRenderer`, and `ScreenPointer` under
  `service/window_manager/`.
- Device-display binding and category-specific behavior:
  `service/device_manager/` and `service/mouse_event_normalize/`.

These anchors are not ownership boundaries by themselves. Follow the call chain
from the API or event entry to the state cache being touched.

## Common Failure Patterns

- Treating a physical display id as if it owns focus, cursor, and window state.
- Updating default-group focus or cursor state after a non-default event has
  already resolved a target group.
- Recomputing target scope during cancel, axis-end, or redispatch instead of
  using the sequence snapshot.
- Moving device-specific binding rules into generic pointer or keyboard helpers.
- Adding tests that only cover the default group for behavior that is supposed
  to be group-isolated.

## Default Group Boundary

Default display group identifiers are valid for default initialization, legacy
helper behavior, and explicit default-group queries.

After an event has resolved to a non-default target scope, target selection,
focus, cursor, capture mode, synthetic events, cancel, axis end, redispatch, and
drawing state should continue using the resolved context or the sequence
snapshot instead of falling back to default-group state.

Default-group state is acceptable for:

- Service startup and default initialization.
- Legacy helper behavior that is explicitly documented as default-group only.
- Read-only default queries that do not allocate optional per-context state.
- Tests that intentionally verify legacy default behavior.

Default-group state is not acceptable after a non-default event chain has
resolved a user/display group or captured a sequence snapshot.

## Decision Checklist

Before changing display-group-sensitive logic, answer these questions in the
patch or test design:

- Which user and display group owns this event or query?
- Is the physical display only an input to group resolution, or is it the final
  behavior scope?
- Does the state being touched affect focus, target selection, coordinates,
  cursor, capture, sequence, redispatch, or drawing?
- What happens when another display group has different focus or pointer state?
- Does cleanup happen when display, user, or device ownership changes?

## Test Mapping

Use `InputWindowsManager*` for focus, target, capture, redispatch, cancel, and
axis-end behavior. Use `InputDisplayBindHelper*` for display binding behavior.
Use `PointerDrawingManager*`, `CursorDrawingComponent*`, and
`PointerDispatchEventCacheStandaloneTest` for cursor, drawing, and sequence
state. Add board-side evidence when behavior depends on real display/window
integration.
