# Input Device Scope Knowledge

This document records stable background for reasoning about the scope of input
devices and events.

## Scope Resolution

Input events should be associated with an explicit runtime scope before code
reads or updates target-sensitive state. A scope can include user, display
group, display, window group, device capability, or sequence state depending on
the feature.

Do not treat an API parameter, a transport identifier, or a compatibility field
as authoritative unless the surrounding subsystem defines it as the runtime
scope. Resolve it first, then pass the resolved context through the event chain.

## Scope Inputs And Authorities

Device id, display id, group id, window id, API token, transport fd, and
compatibility dump fields can all be useful inputs. None of them should become
the routing authority unless the surrounding subsystem explicitly defines that
identifier as the resolved runtime scope.

For new routing or cache decisions, prefer a context object or sequence snapshot
that records the resolved user, display group, display, device category, and
window scope needed by the behavior. Avoid parallel primitive keys that can
drift apart across lifecycle events.

## Device Categories

Different device categories can have different ownership and targeting rules.
Code that changes dispatch or state caches should first identify whether the
path is handling pointer-class, keyboard-class, touch, tablet, joystick, remote,
or virtual input.

Shared helpers should avoid assuming that all input devices use the same
display, focus, cursor, or sequence state.

## Category Guide

- Pointer-class devices usually depend on display group boundaries, coordinate
  range, cursor state, capture state, and pointer sequence snapshots.
- Keyboard-class devices usually depend on the focus state of the resolved
  target scope and subscriber/interceptor ordering.
- Touch and touchpad paths can share pointer containers but differ in gesture,
  hover, tablet, and coordinate transformation rules.
- Tablet and stylus paths can add tool type, proximity, button, pressure, and
  drawing behavior that should not be folded into generic mouse routing without
  checking ownership.
- Joystick, crown, remote, virtual, and injected input may have transport or API
  identifiers that require explicit resolution before target selection.

When adding a shared helper, document which categories it supports and which
scope fields it requires.

## Category Scope Table

| Category | Scope fields to check | Typical anchors |
| --- | --- | --- |
| Pointer or mouse | Device id, display group, display, cursor state, sequence | `service/mouse_event_normalize/`, `service/window_manager/` |
| Keyboard | Device id when relevant, resolved focus group, subscriber/interceptor state | `service/key_event_normalize/`, `InputWindowsManager::UpdateTarget` |
| Touch or touchpad | Device id, display/group transform, gesture state, pointer items | `service/touch_event_normalize/` |
| Tablet or stylus | Device id, tool type, proximity, buttons, pressure, display transform | `TabletToolTransformTest`, touch transform code |
| Joystick, crown, remote | Device capability, transport source, focused scope or configured target | `service/joystick/`, `service/crown_transform_processor/`, remote transform code |
| Virtual or injected input | API caller, token/transport identity, resolved target scope | `interfaces/`, `frameworks/`, dispatch/window manager code |

## Lifecycle

Runtime scope derived from device, display, user, or window state must be
validated when that state changes. Device removal, display removal, user-space
changes, and service restart paths should not leave stale event scope or state
cache entries behind.

Typical cleanup triggers include:

- Device add, remove, enable, disable, or capability change.
- Display add, remove, fold, rotation, or group topology change.
- User switch, foreground group change, or service restart.
- Window destruction, focus transfer, capture release, cancel event, or sequence
  end.

Cleanup should remove or invalidate scoped caches without creating replacement
context state for ordinary default paths.

## Forbidden Shortcuts

- Do not route new behavior directly from `deviceId`, `displayId`, fd, or API
  token unless the subsystem explicitly defines that value as the resolved
  runtime scope.
- Do not fold tablet, stylus, touchpad, remote, or virtual ownership rules into
  mouse routing just because they share `PointerEvent`.
- Do not keep stale device-derived state after hotplug, display topology change,
  user switch, service restart, cancel, or sequence end.
- Do not use dump or compatibility structures as the source of truth for new
  routing decisions.

## Compatibility

Legacy query or dump structures can remain for compatibility, but they should
not become the authority for new event routing decisions. Prefer a resolved
context object over scattered global state or independent primitive keys.

## Code Anchors

- Device discovery, capability, and lifecycle: `service/device_manager/`.
- Device state and hotplug tests: `service/device_manager/test/` and
  `service/libinput_adapter/test/`.
- Mouse/pointer device state: `service/mouse_event_normalize/`.
- Touchpad, tablet, gesture, and remote transforms:
  `service/touch_event_normalize/`.
- Native, NAPI, ETS, and compatibility API surfaces: `interfaces/` and
  `frameworks/`.

## Test Mapping

Use `DeviceManagerTest`, `DeviceManagerExTest`, `InputDeviceManagerTestWithMock`,
`DeviceStateManagerTest`, and `mmi-libadapter-hotplug-test` for lifecycle or
capability changes. Use `MouseEventNormalize*`, `Touch*Transform*`,
`TabletToolTransformTest`, or `RemoteControlTransformProcessorTestWithMock` for
category-specific transform and routing changes. Use `InputNativeTest` when API
compatibility fields are involved.
