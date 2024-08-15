/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
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

#ifndef LIBINPUT_H
#define LIBINPUT_H

#include <stdint.h>

#include "libudev.h"

#ifdef __cplusplus
extern "C" {
#endif

enum libinput_event_type {
    LIBINPUT_EVENT_NONE = 0,

    LIBINPUT_EVENT_KEYBOARD_KEY = 300,

    LIBINPUT_EVENT_POINTER_TAP,
    LIBINPUT_EVENT_POINTER_AXIS,
    LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD,
    LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD,
    LIBINPUT_EVENT_POINTER_BUTTON,
    LIBINPUT_EVENT_POINTER_MOTION,
    LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE,

    LIBINPUT_EVENT_TOUCH_DOWN = 500,
    LIBINPUT_EVENT_TOUCH_UP,
    LIBINPUT_EVENT_TOUCH_MOTION,
    LIBINPUT_EVENT_TOUCH_CANCEL,
    LIBINPUT_EVENT_TOUCH_FRAME,

    LIBINPUT_EVENT_TOUCHPAD_DOWN = 550,
    LIBINPUT_EVENT_TOUCHPAD_UP,
    LIBINPUT_EVENT_TOUCHPAD_MOTION,

    LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN = 800,
    LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE,
    LIBINPUT_EVENT_GESTURE_SWIPE_END,
    LIBINPUT_EVENT_GESTURE_PINCH_BEGIN,
    LIBINPUT_EVENT_GESTURE_PINCH_UPDATE,
    LIBINPUT_EVENT_GESTURE_PINCH_END,

    LIBINPUT_EVENT_TABLET_TOOL_AXIS,
    LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY,
    LIBINPUT_EVENT_TABLET_TOOL_TIP,
};

enum libinput_key_state {
    LIBINPUT_KEY_STATE_RELEASED = 0,
    LIBINPUT_KEY_STATE_PRESSED = 1
};

enum libinput_tablet_tool_tip_state {
    LIBINPUT_TABLET_TOOL_TIP_UP = 0,
    LIBINPUT_TABLET_TOOL_TIP_DOWN = 1,
};

enum libinput_button_state {
    LIBINPUT_BUTTON_STATE_RELEASED = 0,
    LIBINPUT_BUTTON_STATE_PRESSED = 1
};

enum libinput_pointer_axis_source {
    LIBINPUT_POINTER_AXIS_SOURCE_WHEEL = 1,
    LIBINPUT_POINTER_AXIS_SOURCE_FINGER,
    LIBINPUT_POINTER_AXIS_SOURCE_CONTINUOUS,
    LIBINPUT_POINTER_AXIS_SOURCE_WHEEL_TILT,
};

enum libinput_device_capability {
    LIBINPUT_DEVICE_CAP_KEYBOARD = 0,
    LIBINPUT_DEVICE_CAP_POINTER = 1,
    LIBINPUT_DEVICE_CAP_TOUCH = 2,
    LIBINPUT_DEVICE_CAP_TABLET_TOOL = 3,
    LIBINPUT_DEVICE_CAP_TABLET_PAD = 4,
    LIBINPUT_DEVICE_CAP_GESTURE = 5,
    LIBINPUT_DEVICE_CAP_SWITCH = 6,
    LIBINPUT_DEVICE_CAP_JOYSTICK = 7,
};

enum evdev_device_udev_tags {
    EVDEV_UDEV_TAG_INPUT = 1 << 0,
    EVDEV_UDEV_TAG_KEYBOARD = 1 << 1,
    EVDEV_UDEV_TAG_MOUSE = 1 << 2,
    EVDEV_UDEV_TAG_TOUCHPAD = 1 << 3,
    EVDEV_UDEV_TAG_TOUCHSCREEN = 1 << 4,
    EVDEV_UDEV_TAG_TABLET = 1 << 5,
    EVDEV_UDEV_TAG_JOYSTICK = 1 << 6,
    EVDEV_UDEV_TAG_ACCELEROMETER = 1 << 7,
    EVDEV_UDEV_TAG_TABLET_PAD = 1 << 8,
    EVDEV_UDEV_TAG_POINTINGSTICK = 1 << 9,
    EVDEV_UDEV_TAG_TRACKBALL = 1 << 10,
    EVDEV_UDEV_TAG_SWITCH = 1 << 11,
};

enum libinput_tablet_tool_type {
    LIBINPUT_TABLET_TOOL_TYPE_PEN = 1,
    LIBINPUT_TABLET_TOOL_TYPE_ERASER,
    LIBINPUT_TABLET_TOOL_TYPE_BRUSH,
    LIBINPUT_TABLET_TOOL_TYPE_PENCIL,
    LIBINPUT_TABLET_TOOL_TYPE_AIRBRUSH,
    LIBINPUT_TABLET_TOOL_TYPE_MOUSE,
    LIBINPUT_TABLET_TOOL_TYPE_LENS,
    LIBINPUT_TABLET_TOOL_TYPE_TOTEM,
};

enum libinput_pointer_axis {
	LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL = 0,
	LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL = 1,
};

struct udev_device;
struct libinput_device;
struct libinput_event;
struct libinput_event_keyboard;
struct libinput_event_pointer;
struct libinput_event_touch;
struct libinput_event_tablet_tool;
struct libinput_event_gesture;
struct libinput_tablet_tool;

enum libinput_event_type libinput_event_get_type(struct libinput_event *event);

int32_t libinput_event_tablet_tool_get_tool_type(struct libinput_event_tablet_tool *event);

struct libinput_tablet_tool* libinput_event_tablet_tool_get_tool(struct libinput_event_tablet_tool *event);

enum libinput_tablet_tool_type libinput_tablet_tool_get_type(struct libinput_tablet_tool *tool);

enum libinput_tablet_tool_tip_state libinput_event_tablet_tool_get_tip_state(struct libinput_event_tablet_tool *event);

enum libinput_pointer_axis_source libinput_event_pointer_get_axis_source(struct libinput_event_pointer *event);

double libinput_event_tablet_tool_get_tilt_x(struct libinput_event_tablet_tool *event);

double libinput_event_tablet_tool_get_tilt_y(struct libinput_event_tablet_tool *event);

uint64_t libinput_event_tablet_tool_get_time_usec(struct libinput_event_tablet_tool *event);

double libinput_event_tablet_tool_get_pressure(struct libinput_event_tablet_tool *event);

struct libinput_device* libinput_event_get_device(struct libinput_event *event);

uint64_t libinput_event_get_sensortime(struct libinput_event *event);

struct libinput_event_keyboard* libinput_event_get_keyboard_event(struct libinput_event *event);

struct libinput_event_pointer* libinput_event_get_pointer_event(struct libinput_event *event);

struct libinput_event_touch* libinput_event_get_touch_event(struct libinput_event *event);

struct libinput_event_touch* libinput_event_get_touchpad_event(struct libinput_event *event);

struct libinput_event_gesture* libinput_event_get_gesture_event(struct libinput_event *event);

struct libinput_event_tablet_tool* libinput_event_get_tablet_tool_event(struct libinput_event *event);

uint64_t libinput_event_keyboard_get_time_usec(struct libinput_event_keyboard *event);

uint32_t libinput_event_keyboard_get_key(struct libinput_event_keyboard *event);

int libinput_device_keyboard_has_key(struct libinput_device *device, uint32_t code);

enum libinput_key_state libinput_event_keyboard_get_key_state(struct libinput_event_keyboard *event);

enum libinput_button_state libinput_event_pointer_get_button_state(struct libinput_event_pointer *event);

uint64_t libinput_event_touch_get_time_usec(struct libinput_event_touch *event);

int32_t libinput_event_touch_get_seat_slot(struct libinput_event_touch *event);

double libinput_event_touch_get_pressure(struct libinput_event_touch* event);

int32_t libinput_event_touch_get_move_flag(struct libinput_event_touch* event);

int32_t libinput_event_get_touch_contact_long_axis(struct libinput_event_touch *event);

int32_t libinput_event_get_touch_contact_short_axis(struct libinput_event_touch *event);

int32_t libinput_event_touch_get_tool_type(struct libinput_event_touch *event);

int libinput_device_touch_btn_tool_type_down(struct libinput_device *device, int32_t btnToolType);

double libinput_event_touch_get_x_transformed(struct libinput_event_touch *event, uint32_t width);

double libinput_event_touch_get_y_transformed(struct libinput_event_touch *event, uint32_t height);

double libinput_event_touch_get_tool_x_transformed(struct libinput_event_touch *event, uint32_t width);

double libinput_event_touch_get_tool_y_transformed(struct libinput_event_touch *event, uint32_t height);

double libinput_event_touch_get_tool_width_transformed(struct libinput_event_touch *event, uint32_t width);

double libinput_event_touch_get_tool_height_transformed(struct libinput_event_touch *event, uint32_t height);

double libinput_event_tablet_tool_get_x_transformed(struct libinput_event_tablet_tool *event, uint32_t width);

double libinput_event_tablet_tool_get_y_transformed(struct libinput_event_tablet_tool *event, uint32_t height);

uint64_t libinput_event_touchpad_get_time_usec(struct libinput_event_touch *event);

int32_t libinput_event_touchpad_get_seat_slot(struct libinput_event_touch *event);

double libinput_event_touchpad_get_x(struct libinput_event_touch *event);

double libinput_event_touchpad_get_y(struct libinput_event_touch *event);

double libinput_event_touchpad_get_pressure(struct libinput_event_touch *event);

int32_t libinput_event_touchpad_get_touch_contact_long_axis(struct libinput_event_touch *event);

int32_t libinput_event_touchpad_get_touch_contact_short_axis(struct libinput_event_touch *event);

int32_t libinput_event_touchpad_get_tool_type(struct libinput_event_touch *event);

int32_t libinput_device_touchpad_btn_tool_type_down(struct libinput_device *device, int32_t btnToolType);

double libinput_event_touchpad_get_tool_x(struct libinput_event_touch *event);

double libinput_event_touchpad_get_tool_y(struct libinput_event_touch *event);

double libinput_event_touchpad_get_tool_width(struct libinput_event_touch *event);

double libinput_event_touchpad_get_tool_height(struct libinput_event_touch *event);

uint32_t libinput_event_gesture_get_time(struct libinput_event_gesture *event);

int libinput_event_gesture_get_finger_count(struct libinput_event_gesture *event);

double libinput_event_gesture_get_scale(struct libinput_event_gesture *event);

int libinput_event_gesture_get_device_coords_x(struct libinput_event_gesture *event, uint32_t idx);

int libinput_event_gesture_get_device_coords_y(struct libinput_event_gesture *event, uint32_t idx);

int libinput_has_event_led_type(struct libinput_device *device);

const char* libinput_device_get_name(struct libinput_device *device);

unsigned int libinput_device_get_id_bustype(struct libinput_device *device);

unsigned int libinput_device_get_id_version(struct libinput_device *device);

unsigned int libinput_device_get_id_product(struct libinput_device *device);

unsigned int libinput_device_get_id_vendor(struct libinput_device *device);

const char* libinput_device_get_phys(struct libinput_device* device);

const char* libinput_device_get_uniq(struct libinput_device* device);

const char* libinput_device_get_sysname(struct libinput_device *device);

struct udev_device* libinput_device_get_udev_device(struct libinput_device *device);

enum evdev_device_udev_tags libinput_device_get_tags(struct libinput_device* device);

int libinput_device_has_capability(struct libinput_device *device, enum libinput_device_capability capability);

int32_t libinput_device_has_key(struct libinput_device* device, int32_t keyCode);

int32_t libinput_device_get_axis_min(struct libinput_device* device, int32_t code);

int32_t libinput_device_get_axis_max(struct libinput_device* device, int32_t code);

int32_t libinput_device_get_axis_fuzz(struct libinput_device* device, int32_t code);

int32_t libinput_device_get_axis_flat(struct libinput_device* device, int32_t code);

int32_t libinput_device_get_axis_resolution(struct libinput_device* device, int32_t code);

int libinput_get_funckey_state(struct libinput_device *device, unsigned int code);

uint32_t libinput_event_pointer_get_finger_count(struct libinput_event_pointer *event);

double libinput_event_pointer_get_dx_unaccelerated(struct libinput_event_pointer *event);

double libinput_event_pointer_get_dy_unaccelerated(struct libinput_event_pointer *event);

uint32_t libinput_event_pointer_get_button(struct libinput_event_pointer *event);

int libinput_event_pointer_has_axis(struct libinput_event_pointer *event, enum libinput_pointer_axis axis);

double libinput_event_pointer_get_axis_value(struct libinput_event_pointer *event, enum libinput_pointer_axis axis);

#ifdef __cplusplus
}
#endif
#endif /* LIBINPUT_H */