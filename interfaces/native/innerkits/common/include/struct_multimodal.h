/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef OHOS_LIBMMI_STRUCT_H
#define OHOS_LIBMMI_STRUCT_H

#include "proto.h"

#define MAX_DEVICENAME 64
#define MAX_UUIDSIZE 64
#define MAX_SOLTED_COORDS_NUM 10

enum SENIOR_DEVICE_TYPE {
    INPUT_DEVICE_AISENSOR = 31,
    INPUT_DEVICE_KNUCKLE = 41
};

enum HOS_DEVICE_TYPE {
    HOS_UNKNOWN_DEVICE_TYPE = -1,
    HOS_TOUCH_PANEL = 0,
    HOS_KEYBOARD = 1,
    HOS_MOUSE = 2,
    HOS_STYLUS = 3,
    HOS_BUILTIN_KEY = 4,
    HOS_ROTATION = 5,
    HOS_AI_SPEECH = 6,
    HOS_JOYSTICK = 7,
    HOS_TOUCHPAD = 8,
    HOS_KNUCKLE = 9,
};

enum BUTTON_STATE {
    BUTTON_STATE_RELEASED = 0,
    BUTTON_STATE_PRESSED = 1
};

enum KEY_STATE {
    KEY_STATE_RELEASED,
    KEY_STATE_PRESSED
};

enum POINTER_AXIS {
    POINTER_AXIS_SCROLL_VERTICAL = 0,
    POINTER_AXIS_SCROLL_HORIZONTAL = 1,
};

enum POINTER_AXIS_SOURCE {
    POINTER_AXIS_SOURCE_WHEEL = 1,
    POINTER_AXIS_SOURCE_FINGER,
    POINTER_AXIS_SOURCE_CONTINUOUS,
    POINTER_AXIS_SOURCE_WHEEL_TILT,
};

enum TABLE_TOOL_TYPE {
    TABLET_TOOL_TYPE_PEN = 1,
    TABLET_TOOL_TYPE_ERASER,
    TABLET_TOOL_TYPE_BRUSH,
    TABLET_TOOL_TYPE_PENCIL,
    TABLET_TOOL_TYPE_AIRBRUSH,
    TABLET_TOOL_TYPE_MOUSE,
    TABLET_TOOL_TYPE_LENS,
    TABLET_TOOL_TYPE_TOTEM,
};

enum TABLE_TOOL_PROXIMITY_STATE {
    TABLET_TOOL_PROXIMITY_STATE_OUT = 0,
    TABLET_TOOL_PROXIMITY_STATE_IN = 1,
};

enum TABLE_TOOL_TIP_STATE {
    TABLET_TOOL_TIP_UP = 0,
    TABLET_TOOL_TIP_DOWN = 1,
};

enum POINT_EVENT_TYPE {
    EVENT_TYPE_INVALID = 0,
    PRIMARY_POINT_DOWN = 1,
    PRIMARY_POINT_UP = 2,
    POINT_MOVE = 3,
    OTHER_POINT_DOWN = 4,
    OTHER_POINT_UP = 5,
};

enum TABLET_PAD_RING_AXIS_SOURCE {
    TABLET_PAD_RING_SOURCE_UNKNOWN = 1,
    TABLET_PAD_RING_SOURCE_FINGER,
};

enum TABLET_PAD_STRIP_AXIS_SOURCE {
    TABLET_PAD_STRIP_SOURCE_UNKNOWN = 1,
    TABLET_PAD_STRIP_SOURCE_FINGER,
};

#pragma pack(1)
struct TagPackHead {
	MmiMessageId idMsg;
	int32_t sizeEvent[1];
};
#pragma pack()

struct SeniorDeviceInfo {
    char devicePhys[MAX_DEVICENAME];
    enum SENIOR_DEVICE_TYPE seniorDeviceType;
};

struct EventJoyStickAxisAbsInfo {
    int32_t code;
    int32_t value;
    int32_t minimum;
    int32_t maximum;
    int32_t fuzz;
    int32_t flat;
    int32_t resolution;
    float standardValue;
    bool isChanged;
};

struct EventJoyStickAxis {
    uint32_t deviceId;
    char devicePhys[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    HOS_DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    uint64_t time;
    struct EventJoyStickAxisAbsInfo abs_throttle;
    struct EventJoyStickAxisAbsInfo abs_hat0x;
    struct EventJoyStickAxisAbsInfo abs_hat0y;
    struct EventJoyStickAxisAbsInfo abs_x;
    struct EventJoyStickAxisAbsInfo abs_y;
    struct EventJoyStickAxisAbsInfo abs_z;
    struct EventJoyStickAxisAbsInfo abs_rx;
    struct EventJoyStickAxisAbsInfo abs_ry;
    struct EventJoyStickAxisAbsInfo abs_rz;
    struct EventJoyStickAxisAbsInfo abs_wheel;
};

struct NormalizedCoords {
    double x;
    double y;
};

struct DeviceFloatCoords {
    double x;
    double y;
};

struct DeviceCoords {
    double x;
    double y;
};

struct TiltDegrees {
    double x;
    double y;
};

struct DiscreteCoords {
    double x;
    double y;
};

struct PhysEllipsis {
    double major;
    double minor;
};

struct Threshold {
    int32_t upper;
    int32_t lower;
};

struct RegisteredEvent {
    uint32_t deviceId;
    char uuid[MAX_UUIDSIZE];
    int32_t eventType;
    uint64_t occurredTime;
    HOS_DEVICE_TYPE deviceType;
    char devicePhys[MAX_DEVICENAME];
};

struct StandardTouchStruct {
    uint64_t time;
    uint32_t msgType;
    int32_t buttonType;
    int32_t buttonCount;
    int32_t buttonState;
    int32_t reRventType;
    int32_t curRventType;
    int32_t tipState;
    double x;
    double y;
};

struct EventKeyboard {
    uint32_t deviceId;
    char devicePhys[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    HOS_DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    uint64_t time;
    uint32_t key;
    uint32_t seat_key_count;
    enum KEY_STATE state;
    int32_t mUnicode;
};

struct EventPointer {
    uint32_t deviceId;
    char devicePhys[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    HOS_DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    uint64_t time;
    struct NormalizedCoords delta;
    struct DeviceFloatCoords delta_raw;
    struct DeviceCoords absolute;
    struct DiscreteCoords discrete;
    uint32_t button;
    uint32_t seat_button_count;
    enum BUTTON_STATE state;
    enum POINTER_AXIS_SOURCE source;
    enum POINTER_AXIS axes;
};

struct Pointer {
    struct DeviceCoords absolute;
};

struct TabletAxes {
    struct DeviceCoords point;
    struct NormalizedCoords delta;
    double distance;
    double pressure;
    struct TiltDegrees tilt;
    double rotation;
    double slider;
    double wheel;
    int wheel_discrete;
    struct PhysEllipsis size;
};

struct TabletTool {
    uint32_t serial;
    uint32_t tool_id;
    enum TABLE_TOOL_TYPE type;
};

struct EventTabletTool {
    uint32_t deviceId;
    char devicePhys[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    HOS_DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    uint32_t button;
    enum BUTTON_STATE state;
    uint32_t seat_button_count;
    uint64_t time;
    struct TabletAxes axes;
    struct TabletTool tool;
    enum TABLE_TOOL_PROXIMITY_STATE proximity_state;
    enum TABLE_TOOL_TIP_STATE tip_state;
};

struct EventTouch {
    uint32_t deviceId;
    char devicePhys[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    char uuid[MAX_UUIDSIZE];
    int32_t eventType;
    uint64_t time;
    int32_t slot;
    int32_t seat_slot;
    struct DeviceCoords point;
    HOS_DEVICE_TYPE deviceType;
    double pressure;
    double area;
};

struct SlotedCoords {
    bool isActive;
    float x;
    float y;
};

struct SlotedCoordsInfo {
    struct SlotedCoords coords[MAX_SOLTED_COORDS_NUM];
    uint32_t activeCount;
};

struct EventGesture {
    uint32_t deviceId;
    char devicePhys[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    HOS_DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    uint64_t time;
    int32_t fingerCount;
    int32_t cancelled;
    struct NormalizedCoords delta;
    struct NormalizedCoords deltaUnaccel;
    struct SlotedCoordsInfo soltTouches;
};

struct RawInputEvent {
    uint32_t stamp;
    uint32_t ev_type;
    uint32_t ev_code;
    uint32_t ev_value;
};

struct TestSurfaceData {
    int32_t screenId;
    int32_t onLayerId;
    int32_t surfaceId;
    int32_t opacity;
    int32_t visibility;
    int32_t srcX;
    int32_t srcY;
    int32_t srcW;
    int32_t srcH;
};

struct VirtualKey {
    bool isPressed;
    int32_t keyCode;
    int32_t keyDownDuration;
    int32_t maxKeyCode;
};

struct DeviceManage {
    uint32_t deviceId;
    char devicePhys[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    HOS_DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
};

struct EventTabletPad {
    uint32_t deviceId;
    char devicePhys[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    HOS_DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    uint64_t time;
    uint32_t mode;
    struct {
        uint32_t number;
        enum BUTTON_STATE state;
    } button;
    struct {
        uint32_t code;
        enum KEY_STATE state;
    } key;
    struct {
        enum TABLET_PAD_RING_AXIS_SOURCE source;
        double position;
        int32_t number;
    } ring;
    struct {
        enum TABLET_PAD_STRIP_AXIS_SOURCE source;
        double position;
        int number;
    } strip;
};

#endif