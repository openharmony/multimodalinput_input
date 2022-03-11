/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef STRUCT_MULTIMODAL_H
#define STRUCT_MULTIMODAL_H

#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_DEVICENAME = 64;
constexpr int32_t MAX_UUIDSIZE = 64;
constexpr int32_t SYSTEMUID = 1000;
constexpr int32_t MAX_SOLTED_COORDS_NUMS = 10;
} // namespace

enum SENIOR_DEVICE_TYPE {
    INPUT_DEVICE_AISENSOR = 31,
    INPUT_DEVICE_KNUCKLE = 41
};

enum DEVICE_TYPE {
    DEVICE_TYPE_UNKNOWN = -1,
    DEVICE_TYPE_TOUCH_PANEL = 0,
    DEVICE_TYPE_KEYBOARD = 1,
    DEVICE_TYPE_MOUSE = 2,
    DEVICE_TYPE_STYLUS = 3,
    DEVICE_TYPE_BUILTIN_KEY = 4,
    DEVICE_TYPE_ROTATION = 5,
    DEVICE_TYPE_AI_SPEECH = 6,
    DEVICE_TYPE_JOYSTICK = 7,
    DEVICE_TYPE_TOUCHPAD = 8,
    DEVICE_TYPE_KNUCKLE = 9,
    DEVICE_TYPE_VIRTUAL_KEYBOARD = 10,
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
    char physical[MAX_DEVICENAME];
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
    int32_t deviceId;
    char physical[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    int64_t time;
    EventJoyStickAxisAbsInfo abs_throttle;
    EventJoyStickAxisAbsInfo abs_hat0x;
    EventJoyStickAxisAbsInfo abs_hat0y;
    EventJoyStickAxisAbsInfo abs_x;
    EventJoyStickAxisAbsInfo abs_y;
    EventJoyStickAxisAbsInfo abs_z;
    EventJoyStickAxisAbsInfo abs_rx;
    EventJoyStickAxisAbsInfo abs_ry;
    EventJoyStickAxisAbsInfo abs_rz;
    EventJoyStickAxisAbsInfo abs_wheel;
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
    int32_t deviceId;
    char uuid[MAX_UUIDSIZE];
    int32_t eventType;
    int64_t occurredTime;
    DEVICE_TYPE deviceType;
    char physical[MAX_DEVICENAME];
};

struct StandardTouchStruct {
    int64_t time;
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
    int32_t deviceId;
    char physical[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    int64_t time;
    int32_t key;
    uint32_t seat_key_count;
    enum KEY_STATE state;
    int32_t unicode;
    bool isIntercepted {true};
};

struct EventPointer {
    int32_t deviceId;
    char physical[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    int64_t time;
    NormalizedCoords delta;
    DeviceFloatCoords delta_raw;
    DeviceCoords absolute;
    DiscreteCoords discrete;
    int32_t button;
    int32_t seat_button_count;
    enum BUTTON_STATE state;
    enum POINTER_AXIS_SOURCE source;
    enum POINTER_AXIS axis;
};

struct Pointer {
    DeviceCoords absolute;
};

struct TabletAxes {
    DeviceCoords point;
    NormalizedCoords delta;
    double distance;
    double pressure;
    TiltDegrees tilt;
    double rotation;
    double slider;
    double wheel;
    int32_t wheel_discrete;
    PhysEllipsis size;
};

struct TabletTool {
    uint32_t serial;
    uint32_t tool_id;
    enum TABLE_TOOL_TYPE type;
};

struct EventTabletTool {
    int32_t deviceId;
    char physical[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    uint32_t button;
    enum BUTTON_STATE state;
    uint32_t seat_button_count;
    int64_t time;
    TabletAxes axes;
    TabletTool tool;
    enum TABLE_TOOL_PROXIMITY_STATE proximity_state;
    enum TABLE_TOOL_TIP_STATE tip_state;
};

struct EventTouch {
    int32_t deviceId;
    char physical[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    char uuid[MAX_UUIDSIZE];
    int32_t eventType;
    int64_t time;
    int32_t slot;
    int32_t seatSlot;
    DeviceCoords point;
    DEVICE_TYPE deviceType;
    double pressure;
    double area;
};

struct SlotedCoords {
    bool isActive;
    float x;
    float y;
};

struct SlotedCoordsInfo {
    SlotedCoords coords[MAX_SOLTED_COORDS_NUMS];
    uint32_t activeCount;
};

struct EventGesture {
    int32_t deviceId;
    char physical[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    int64_t time;
    int32_t fingerCount;
    int32_t cancelled;
    NormalizedCoords delta;
    NormalizedCoords deltaUnaccel;
    SlotedCoordsInfo soltTouches;
    double scale;
    double angle;
    int32_t pointerEventType;
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
    int64_t keyDownDuration;
    bool isIntercepted {true};
};

struct DeviceManage {
    uint32_t deviceId;
    char physical[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
};

struct EventTabletPad {
    uint32_t deviceId;
    char physical[MAX_DEVICENAME];
    char deviceName[MAX_DEVICENAME];
    DEVICE_TYPE deviceType;
    int32_t eventType;
    char uuid[MAX_UUIDSIZE];
    int64_t time;
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
        int32_t number;
    } strip;
};
} // namespace MMI
} // namespace OHOS

#endif // STRUCT_MULTIMODAL_H