/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
{}
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "libinput_interface.h"

namespace {
OHOS::MMI::LibinputInterface *g_instance = nullptr;
} // namespace

namespace OHOS {
namespace MMI {

LibinputInterface::LibinputInterface()
{
    g_instance = this;
}
} // namespace MMI
} // namespace OHOS

extern "C" {
enum libinput_event_type libinput_event_get_type(struct libinput_event *event)
{
    return g_instance->GetEventType(event);
}

enum libinput_tablet_tool_tip_state libinput_event_tablet_tool_get_tip_state(struct libinput_event_tablet_tool *event)
{
    return g_instance->TabletToolGetTipState(event);
}

double libinput_event_tablet_tool_get_tilt_x(struct libinput_event_tablet_tool *event)
{
    return g_instance->TabletToolGetTiltX(event);
}

enum libinput_pointer_axis_source libinput_event_pointer_get_axis_source(struct libinput_event_pointer *event)
{
    return g_instance->GetAxisSource(event);
}

double libinput_event_tablet_tool_get_tilt_y(struct libinput_event_tablet_tool *event)
{
    return g_instance->TabletToolGetTiltY(event);
}

uint64_t libinput_event_tablet_tool_get_time_usec(struct libinput_event_tablet_tool *event)
{
    return g_instance->TabletToolGetTimeUsec(event);
}

double libinput_event_tablet_tool_get_pressure(struct libinput_event_tablet_tool *event)
{
    return g_instance->TabletToolGetPressure(event);
}

int32_t libinput_event_tablet_tool_get_tool_type(struct libinput_event_tablet_tool *event)
{
    return g_instance->TabletToolGetToolType(event);
}

enum libinput_tablet_tool_type libinput_tablet_tool_get_type(struct libinput_tablet_tool *tool)
{
    return g_instance->TabletToolGetType(tool);
}

struct libinput_tablet_tool* libinput_event_tablet_tool_get_tool(struct libinput_event_tablet_tool *event)
{
    return g_instance->TabletToolGetTool(event);
}

struct libinput_device* libinput_event_get_device(struct libinput_event *event)
{
    return g_instance->GetDevice(event);
}

uint64_t libinput_event_get_sensortime(struct libinput_event *event)
{
    return g_instance->GetSensorTime(event);
}

struct libinput_event_keyboard* libinput_event_get_keyboard_event(struct libinput_event *event)
{
    return (event != nullptr ? reinterpret_cast<libinput_event_keyboard *>(event) : nullptr);
}

struct libinput_event_pointer* libinput_event_get_pointer_event(struct libinput_event *event)
{
    return g_instance->LibinputGetPointerEvent(event);
}

struct libinput_event_touch* libinput_event_get_touch_event(struct libinput_event *event)
{
    return g_instance->GetTouchEvent(event);
}

struct libinput_event_touch* libinput_event_get_touchpad_event(struct libinput_event *event)
{
    return g_instance->GetTouchpadEvent(event);
}

struct libinput_event_gesture* libinput_event_get_gesture_event(struct libinput_event *event)
{
    return g_instance->GetGestureEvent(event);
}

struct libinput_event_tablet_tool* libinput_event_get_tablet_tool_event(struct libinput_event *event)
{
    return g_instance->GetTabletToolEvent(event);
}

uint64_t libinput_event_keyboard_get_time_usec(struct libinput_event_keyboard *event)
{
    return (event != nullptr ? event->base.time : 0);
}

uint32_t libinput_event_keyboard_get_key(struct libinput_event_keyboard *event)
{
    return (event != nullptr ? event->key : 0);
}

int libinput_device_keyboard_has_key(struct libinput_device *device, uint32_t code)
{
    return 0;
}

enum libinput_key_state libinput_event_keyboard_get_key_state(struct libinput_event_keyboard *event)
{
    return (event != nullptr ? event->keyState : LIBINPUT_KEY_STATE_RELEASED);
}

enum libinput_button_state libinput_event_pointer_get_button_state(struct libinput_event_pointer *event)
{
    return (event != nullptr ? event->buttonState : LIBINPUT_BUTTON_STATE_RELEASED);
}

uint64_t libinput_event_touch_get_time_usec(struct libinput_event_touch *event)
{
    return g_instance->TouchEventGetTime(event);
}

int32_t libinput_event_touch_get_seat_slot(struct libinput_event_touch *event)
{
    return g_instance->TouchEventGetSeatSlot(event);
}

double libinput_event_touch_get_pressure(struct libinput_event_touch* event)
{
    return g_instance->TouchEventGetPressure(event);
}

int32_t libinput_event_get_touch_contact_long_axis(struct libinput_event_touch *event)
{
    return g_instance->TouchEventGetContactLongAxis(event);
}

int32_t libinput_event_get_touch_contact_short_axis(struct libinput_event_touch *event)
{
    return g_instance->TouchEventGetContactShortAxis(event);
}

int32_t libinput_event_touch_get_tool_type(struct libinput_event_touch *event)
{
    return g_instance->TouchEventGetToolType(event);
}

int libinput_device_touch_btn_tool_type_down(struct libinput_device *device, int32_t btnToolType)
{
    return g_instance->TouchEventGetBtnToolTypeDown(device, btnToolType);
}

double libinput_event_touch_get_x_transformed(struct libinput_event_touch *event, uint32_t width)
{
    return -1.0;
}

double libinput_event_touch_get_y_transformed(struct libinput_event_touch *event, uint32_t height)
{
    return -1.0;
}

double libinput_event_touch_get_tool_x_transformed(struct libinput_event_touch *event, uint32_t width)
{
    return -1.0;
}

double libinput_event_touch_get_tool_y_transformed(struct libinput_event_touch *event, uint32_t height)
{
    return -1.0;
}

double libinput_event_touch_get_tool_width_transformed(struct libinput_event_touch *event, uint32_t width)
{
    return -1.0;
}

double libinput_event_touch_get_tool_height_transformed(struct libinput_event_touch *event, uint32_t height)
{
    return -1.0;
}

double libinput_event_tablet_tool_get_x_transformed(struct libinput_event_tablet_tool *event, uint32_t width)
{
    return -1.0;
}

double libinput_event_tablet_tool_get_y_transformed(struct libinput_event_tablet_tool *event, uint32_t height)
{
    return -1.0;
}

uint64_t libinput_event_touchpad_get_time_usec(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->base.time : 0);
}

int32_t libinput_event_touchpad_get_seat_slot(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->seatSlot : 0);
}

double libinput_event_touchpad_get_x(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->x : 0.0);
}

double libinput_event_touchpad_get_y(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->y : 0.0);
}

double libinput_event_touchpad_get_pressure(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->pressure : 0.0);
}

int32_t libinput_event_touchpad_get_touch_contact_long_axis(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->longAxis : 0);
}

int32_t libinput_event_touchpad_get_touch_contact_short_axis(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->shortAxis : 0);
}

int32_t libinput_event_touchpad_get_tool_type(struct libinput_event_touch *event)
{
    return g_instance->TouchpadGetTool(event);
}

int32_t libinput_device_touchpad_btn_tool_type_down(struct libinput_device *device, int32_t btnToolType)
{
    return -1;
}

double libinput_event_touchpad_get_tool_x(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->toolX : 0.0);
}

double libinput_event_touchpad_get_tool_y(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->toolY : 0.0);
}

double libinput_event_touchpad_get_tool_width(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->toolWidth : 0.0);
}

double libinput_event_touchpad_get_tool_height(struct libinput_event_touch *event)
{
    return (event != nullptr ? event->toolWidth : 0.0);
}

uint32_t libinput_event_gesture_get_time(struct libinput_event_gesture *event)
{
    return g_instance->GestureEventGetTime(event);
}

int libinput_event_gesture_get_finger_count(struct libinput_event_gesture *event)
{
    return g_instance->GestureEventGetFingerCount(event);
}

double libinput_event_gesture_get_scale(struct libinput_event_gesture *event)
{
    return (event != nullptr ? static_cast<uint32_t>(event->scale) : 1.0);
}

int libinput_event_gesture_get_device_coords_x(struct libinput_event_gesture *event, uint32_t idx)
{
    return g_instance->GestureEventGetDevCoordsX(event, idx);
}

int libinput_event_gesture_get_device_coords_y(struct libinput_event_gesture *event, uint32_t idx)
{
    return g_instance->GestureEventGetDevCoordsY(event, idx);
}

int libinput_has_event_led_type(struct libinput_device *device)
{
    return 0;
}

const char* libinput_device_get_name(struct libinput_device *device)
{
    return g_instance->DeviceGetName(device);
}

unsigned int libinput_device_get_id_bustype(struct libinput_device *device)
{
    return (device != nullptr ? device->busType : 0);
}

unsigned int libinput_device_get_id_version(struct libinput_device *device)
{
    return (device != nullptr ? device->version : 0);
}

unsigned int libinput_device_get_id_product(struct libinput_device *device)
{
    return (device != nullptr ? device->product : 0);
}

unsigned int libinput_device_get_id_vendor(struct libinput_device *device)
{
    return (device != nullptr ? device->vendor : 0);
}

const char* libinput_device_get_phys(struct libinput_device* device)
{
    return "";
}

const char* libinput_device_get_uniq(struct libinput_device* device)
{
    return "";
}

const char* libinput_device_get_sysname(struct libinput_device *device)
{
    return nullptr;
}

struct udev_device* libinput_device_get_udev_device(struct libinput_device *device)
{
    return nullptr;
}

enum evdev_device_udev_tags libinput_device_get_tags(struct libinput_device* device)
{
    return EVDEV_UDEV_TAG_INPUT;
}

int libinput_device_has_capability(struct libinput_device *device, enum libinput_device_capability capability)
{
    return 0;
}

int32_t libinput_device_has_key(struct libinput_device* device, int32_t keyCode)
{
    return 0;
}

int32_t libinput_device_get_axis_min(struct libinput_device* device, int32_t code)
{
    return -1;
}

int32_t libinput_device_get_axis_max(struct libinput_device* device, int32_t code)
{
    return -1;
}

int32_t libinput_device_get_axis_fuzz(struct libinput_device* device, int32_t code)
{
    return -1;
}

int32_t libinput_device_get_axis_flat(struct libinput_device* device, int32_t code)
{
    return -1;
}

int32_t libinput_device_get_axis_resolution(struct libinput_device* device, int32_t code)
{
    return -1;
}

int libinput_get_funckey_state(struct libinput_device *device, unsigned int code)
{
    return 0;
}

uint32_t libinput_event_pointer_get_finger_count(struct libinput_event_pointer *event)
{
    return g_instance->PointerEventGetFingerCount(event);
}

double libinput_event_pointer_get_dx_unaccelerated(struct libinput_event_pointer *event)
{
    return g_instance->PointerGetDxUnaccelerated(event);
}

double libinput_event_pointer_get_dy_unaccelerated(struct libinput_event_pointer *event)
{
    return g_instance->PointerGetDyUnaccelerated(event);
}

uint32_t libinput_event_pointer_get_button(struct libinput_event_pointer *event)
{
    return g_instance->PointerGetButton(event);
}

int libinput_event_pointer_has_axis(struct libinput_event_pointer *event, enum libinput_pointer_axis axis)
{
    return g_instance->PointerHasAxis(event, axis);
}

double libinput_event_pointer_get_axis_value(struct libinput_event_pointer *event, enum libinput_pointer_axis axis)
{
    return g_instance->PointerGetAxisValue(event, axis);
}
} // extern "C"
