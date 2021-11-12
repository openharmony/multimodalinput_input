/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "event_package.h"
#include "mmi_server.h"

namespace OHOS {
namespace MMI {
static void FillEventJoyStickAxisAbsInfo(EventJoyStickAxisAbsInfo& l,
                                         const libinput_event_joystick_axis_abs_info& r)
{
    l.code = r.code;
    l.value = r.value;
    l.minimum = r.minimum;
    l.maximum = r.maximum;
    l.fuzz = r.fuzz;
    l.flat = r.flat;
    l.resolution = r.resolution;
    l.standardValue = r.standardValue;
    l.isChanged = true;
}

static void FillEventSlotedCoordsInfo(SlotedCoordsInfo& l, const sloted_coords_info& r)
{
    l.activeCount = r.active_count;
    for (int i = 0; i < MAX_SOLTED_COORDS_NUM; i++) {
        l.coords[i].isActive = r.coords[i].is_active;
        l.coords[i].x = r.coords[i].x;
        l.coords[i].y = r.coords[i].y;
    }
}

static enum HOS_DEVICE_TYPE GetDeviceType(struct libinput_device* device)
{
    enum HOS_DEVICE_TYPE deviceType = HOS_UNKNOWN_DEVICE_TYPE;
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    if (udevTags & EVDEV_UDEV_TAG_JOYSTICK) {
        deviceType = HOS_JOYSTICK;
    } else if (udevTags & EVDEV_UDEV_TAG_KEYBOARD) {
        deviceType = HOS_KEYBOARD;
    } else if (udevTags & (EVDEV_UDEV_TAG_MOUSE | EVDEV_UDEV_TAG_TRACKBALL | EVDEV_UDEV_TAG_POINTINGSTICK)) {
        deviceType = HOS_MOUSE;
    } else if (udevTags & EVDEV_UDEV_TAG_TOUCHSCREEN) {
        deviceType = HOS_TOUCH_PANEL;
    } else if (udevTags & (EVDEV_UDEV_TAG_TOUCHPAD | EVDEV_UDEV_TAG_TABLET_PAD)) {
        deviceType = HOS_TOUCHPAD;
    } else if (udevTags & EVDEV_UDEV_TAG_TABLET) {
        deviceType = HOS_STYLUS;
    } else {
        deviceType = HOS_UNKNOWN_DEVICE_TYPE;
    }
    return deviceType;
}

EventPackage::EventPackage()
{
}

EventPackage::~EventPackage()
{
}

template<class EventType>
int32_t EventPackage::PackageEventDeviceInfo(libinput_event& event, EventType& eventData, UDSServer& udsServer)
{
    auto type = libinput_event_get_type(&event);
    auto device = libinput_event_get_device(&event);
    CHKR(device, NULL_POINTER, LIBINPUT_DEV_EMPTY);
    eventData.eventType = type;
    eventData.deviceType = GetDeviceType(device);
    auto name = libinput_device_get_name(device);
    CHKR(name, NULL_POINTER, RET_ERR);
    CHKR(EOK == memcpy_s(eventData.deviceName, sizeof(eventData.deviceName),
        name, MAX_DEVICENAME), MEMCPY_SEC_FUN_FAIL, RET_ERR);
    const std::string uuid = GetUUid();
    CHKR(EOK == memcpy_s(eventData.uuid, MAX_UUIDSIZE, uuid.c_str(), uuid.size()), MEMCPY_SEC_FUN_FAIL, RET_ERR);
#ifdef OHOS_BUILD_HDF
    CHKR(EOK == memcpy_s(eventData.devicePhys, MAX_DEVICENAME, eventData.deviceName, MAX_DEVICENAME),
        MEMCPY_SEC_FUN_FAIL, RET_ERR);
#else
    auto physWhole = libinput_device_get_phys(device);
    if (!physWhole) {
        CHKR(EOK == memcpy_s(eventData.devicePhys, sizeof(eventData.devicePhys),
             eventData.deviceName, sizeof(eventData.deviceName)), MEMCPY_SEC_FUN_FAIL, RET_ERR);
    } else {
        std::string s(physWhole);
        std::string phys = s.substr(0, s.rfind('/'));
        CHKR(!phys.empty(), NULL_POINTER, RET_ERR);
        CHKR(EOK == memcpy_s(eventData.devicePhys, sizeof(eventData.devicePhys), phys.c_str(), MAX_DEVICENAME),
             MEMCPY_SEC_FUN_FAIL, RET_ERR);
    }
#endif
    std::string devicePhys(eventData.devicePhys);
    if (type == LIBINPUT_EVENT_DEVICE_REMOVED) {
        DevRegister->DeleteDeviceInfo(devicePhys);
        return RET_OK;
    }
    uint32_t deviceId = DevRegister->FindDeviceIdByDevicePhys(devicePhys);
    if (deviceId) {
        eventData.deviceId = deviceId;
    } else {
        deviceId = DevRegister->AddDeviceInfo(devicePhys);
        CHKR(deviceId, ADD_DEVICE_INFO_CALL_FAIL, RET_ERR);
        eventData.deviceId = deviceId;
    }
    return RET_OK;
}

int32_t EventPackage::PackageTabletToolOtherParams(libinput_event& event, EventTabletTool& tableTool)
{
    auto type = libinput_event_get_type(&event);
    auto data = libinput_event_get_tablet_tool_event(&event);
    CHKR(data, NULL_POINTER, RET_ERR);
    auto tool = libinput_event_tablet_tool_get_tool(data);
    CHKR(tool, NULL_POINTER, RET_ERR);
    tableTool.tool.tool_id = libinput_tablet_tool_get_tool_id(tool);
    tableTool.tool.serial = libinput_tablet_tool_get_serial(tool);
    tableTool.axes.point.x = libinput_event_tablet_tool_get_dx(data);
    tableTool.axes.point.y = libinput_event_tablet_tool_get_dy(data);
    tableTool.axes.tilt.x = libinput_event_tablet_tool_get_tilt_x(data);
    tableTool.axes.tilt.y = libinput_event_tablet_tool_get_tilt_y(data);
    tableTool.axes.distance = libinput_event_tablet_tool_get_distance(data);
    tableTool.axes.pressure = libinput_event_tablet_tool_get_pressure(data);
    tableTool.axes.rotation = libinput_event_tablet_tool_get_rotation(data);
    tableTool.axes.slider = libinput_event_tablet_tool_get_slider_position(data);
    tableTool.axes.wheel = libinput_event_tablet_tool_get_wheel_delta(data);
    tableTool.axes.wheel_discrete = libinput_event_tablet_tool_get_wheel_delta_discrete(data);
    tableTool.axes.size.major = libinput_event_tablet_tool_get_size_major(data);
    tableTool.axes.size.minor = libinput_event_tablet_tool_get_size_minor(data);
    if (libinput_event_tablet_tool_get_proximity_state(data) == 0) {
        tableTool.proximity_state = TABLET_TOOL_PROXIMITY_STATE_OUT;
    } else {
        tableTool.proximity_state = TABLET_TOOL_PROXIMITY_STATE_IN;
    }
    if (libinput_event_tablet_tool_get_tip_state(data) == 0) {
        tableTool.tip_state = TABLET_TOOL_TIP_UP;
    } else {
        tableTool.tip_state = TABLET_TOOL_TIP_DOWN;
    }
    if (type == LIBINPUT_EVENT_TABLET_TOOL_BUTTON) {
        tableTool.button = libinput_event_tablet_tool_get_button(data);
        if (libinput_event_tablet_tool_get_button_state(data) == 0) {
            tableTool.state = BUTTON_STATE_RELEASED;
        } else {
            tableTool.state = BUTTON_STATE_PRESSED;
        }
        tableTool.seat_button_count = libinput_event_tablet_tool_get_seat_button_count(data);
        // Ignore button events that are not seat wide state changes.
        if (tableTool.state == BUTTON_STATE_PRESSED && tableTool.seat_button_count != SEAT_BUTTON_OR_KEY_COUNT_ONE) {
            return MULTIDEVICE_SAME_EVENT_FAIL;
        }
        if (tableTool.state == BUTTON_STATE_RELEASED && tableTool.seat_button_count != SEAT_BUTTON_OR_KEY_COUNT_ZERO) {
            return MULTIDEVICE_SAME_EVENT_FAIL;
        }
    }
    return RET_OK;
}
void EventPackage::PackageTabletToolTypeParam(libinput_event& event, EventTabletTool& tableTool)
{
    auto data = libinput_event_get_tablet_tool_event(&event);
    CHK(data != nullptr, NULL_POINTER);
    auto tool = libinput_event_tablet_tool_get_tool(data);
    CHK(tool != nullptr, NULL_POINTER);
    switch (libinput_tablet_tool_get_type(tool)) {
        case LIBINPUT_TABLET_TOOL_TYPE_PEN: {
            tableTool.tool.type = TABLET_TOOL_TYPE_PEN;
            break;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_ERASER: {
            tableTool.tool.type = TABLET_TOOL_TYPE_ERASER;
            break;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_BRUSH: {
            tableTool.tool.type = TABLET_TOOL_TYPE_BRUSH;
            break;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_PENCIL: {
            tableTool.tool.type = TABLET_TOOL_TYPE_PENCIL;
            break;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_AIRBRUSH: {
            tableTool.tool.type = TABLET_TOOL_TYPE_AIRBRUSH;
            break;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_MOUSE: {
            tableTool.tool.type = TABLET_TOOL_TYPE_MOUSE;
            break;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_LENS: {
            tableTool.tool.type = TABLET_TOOL_TYPE_LENS;
            break;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_TOTEM: {
            tableTool.tool.type = TABLET_TOOL_TYPE_TOTEM;
            break;
        }
        default: {
            break;
        }
    }
}

int32_t EventPackage::PackageTabletToolEvent(libinput_event& event, EventTabletTool& tableTool, UDSServer& udsServer)
{
    const uint32_t stylusButton1KeyCode = 331;
    const uint32_t stylusButton2KeyCode = 332;
    const uint32_t stylusButton1Value = 1;
    const uint32_t stylusButton2Value = 2;
    auto data = libinput_event_get_tablet_tool_event(&event);
    CHKR(data, NULL_POINTER, RET_ERR);
    auto tool = libinput_event_tablet_tool_get_tool(data);
    CHKR(tool, NULL_POINTER, RET_ERR);
    auto rDevRet = PackageEventDeviceInfo<EventTabletTool>(event, tableTool, udsServer);
    if (rDevRet != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", rDevRet, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    tableTool.time = libinput_event_tablet_tool_get_time(data);
    PackageTabletToolTypeParam(event, tableTool);
    auto ret = PackageTabletToolOtherParams(event, tableTool);
    if (tableTool.button == stylusButton1KeyCode) {
        tableTool.button = stylusButton1Value;
    } else if (tableTool.button == stylusButton2KeyCode) {
        tableTool.button = stylusButton2Value;
    }
    return ret;
}
void EventPackage::PackageTabletPadOtherParams(libinput_event& event, EventTabletPad& tabletPad)
{
    auto data = libinput_event_get_tablet_pad_event(&event);
    CHK(data != nullptr, NULL_POINTER);
    auto type = libinput_event_get_type(&event);
    switch (type) {
        case LIBINPUT_EVENT_TABLET_PAD_RING: {
            tabletPad.ring.number = libinput_event_tablet_pad_get_ring_number(data);
            tabletPad.ring.position = libinput_event_tablet_pad_get_ring_position(data);
            if (libinput_event_tablet_pad_get_ring_source(data) == 1) {
                tabletPad.ring.source = TABLET_PAD_RING_SOURCE_UNKNOWN;
            } else {
                tabletPad.ring.source = TABLET_PAD_RING_SOURCE_FINGER;
            }
            break;
        }
        case LIBINPUT_EVENT_TABLET_PAD_STRIP: {
            tabletPad.strip.number = libinput_event_tablet_pad_get_strip_number(data);
            tabletPad.strip.position = libinput_event_tablet_pad_get_strip_position(data);
            if (libinput_event_tablet_pad_get_strip_source(data) == 1) {
                tabletPad.strip.source = TABLET_PAD_STRIP_SOURCE_UNKNOWN;
            } else {
                tabletPad.strip.source = TABLET_PAD_STRIP_SOURCE_FINGER;
            }
            break;
        }
        default: {
            break;
        }
    }
}

int32_t EventPackage::PackageTabletPadEvent(libinput_event& event, EventTabletPad& tabletPad, UDSServer& udsServer)
{
    auto data = libinput_event_get_tablet_pad_event(&event);
    CHKR(data, NULL_POINTER, RET_ERR);
    tabletPad.mode = libinput_event_tablet_pad_get_mode(data);
    tabletPad.time = libinput_event_tablet_pad_get_time_usec(data);
    auto ret = PackageEventDeviceInfo<EventTabletPad>(event, tabletPad, udsServer);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    PackageTabletPadOtherParams(event, tabletPad);
    return RET_OK;
}

int32_t EventPackage::PackageTabletPadKeyEvent(libinput_event& event, EventKeyboard& key, UDSServer& udsServer)
{
    auto data = libinput_event_get_tablet_pad_event(&event);
    CHKR(data, NULL_POINTER, RET_ERR);
    auto type = libinput_event_get_type(&event);
    key.time = libinput_event_tablet_pad_get_time_usec(data);
    auto ret = PackageEventDeviceInfo<EventKeyboard>(event, key, udsServer);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    switch (type) {
        case LIBINPUT_EVENT_TABLET_PAD_BUTTON: {
            key.key = libinput_event_tablet_pad_get_button_number(data) | TabletPadButtonNumberPrefix;
            key.seat_key_count = libinput_event_tablet_pad_get_button_state(data);
            if (libinput_event_tablet_pad_get_button_state(data) == 0) {
                key.state = KEY_STATE_RELEASED;
            } else {
                key.state = KEY_STATE_PRESSED;
            }
            break;
        }
        case LIBINPUT_EVENT_TABLET_PAD_KEY: {
            key.key = libinput_event_tablet_pad_get_key(data);
            key.seat_key_count = libinput_event_tablet_pad_get_key_state(data);
            if (libinput_event_tablet_pad_get_key_state(data) == 0) {
                key.state = KEY_STATE_RELEASED;
            } else {
                key.state = KEY_STATE_PRESSED;
            }
            break;
        }
        default: {
            break;
        }
    }
    // Ignore key events that are not seat wide state changes.
    if (key.state == KEY_STATE_PRESSED && key.seat_key_count != SEAT_BUTTON_OR_KEY_COUNT_ONE) {
        return MULTIDEVICE_SAME_EVENT_FAIL;
    }
    if (key.state == KEY_STATE_RELEASED && key.seat_key_count != SEAT_BUTTON_OR_KEY_COUNT_ZERO) {
        return MULTIDEVICE_SAME_EVENT_FAIL;
    }
    return RET_OK;
}

int32_t EventPackage::PackageJoyStickKeyEvent(libinput_event& event, EventKeyboard& key, UDSServer& udsServer)
{
    auto data = libinput_event_get_joystick_pointer_button_event(&event);
    CHKR(data, NULL_POINTER, RET_ERR);
    key.time = libinput_event_joystick_button_time(data);
    key.key = libinput_event_joystick_button_get_key(data);
    auto ret = PackageEventDeviceInfo<EventKeyboard>(event, key, udsServer);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    key.seat_key_count = libinput_event_joystick_button_get_seat_key_count(data);
    if (libinput_event_joystick_button_get_key_state(data) == 0) {
        key.state = KEY_STATE_RELEASED;
    } else {
        key.state = KEY_STATE_PRESSED;
    }
    return RET_OK;
}

void EventPackage::PackagePointerEventByMotion(libinput_event& event,
                                               EventPointer& point, WindowSwitch& windowSwitch)
{
    auto data = libinput_event_get_pointer_event(&event);
    CHK(data != nullptr, PARAM_INPUT_INVALID);

    point.time = libinput_event_pointer_get_time_usec(data);
    point.delta.x = libinput_event_pointer_get_dx(data);
    point.delta.y = libinput_event_pointer_get_dy(data);
    point.delta_raw.x = libinput_event_pointer_get_dx_unaccelerated(data);
    point.delta_raw.y = libinput_event_pointer_get_dy_unaccelerated(data);
    EventPointer absPointer = windowSwitch.GetEventPointer();
    absPointer.delta.x = point.delta.x;
    absPointer.delta.y = point.delta.y;
    absPointer.delta_raw.x = point.delta_raw.x;
    absPointer.delta_raw.y = point.delta_raw.y;
    windowSwitch.SetPointerByMotion(absPointer);
}

void EventPackage::PackagePointerEventByMotionAbs(libinput_event& event,
                                                  EventPointer& point, WindowSwitch& windowSwitch)
{
    auto data = libinput_event_get_pointer_event(&event);
    CHK(data != nullptr, PARAM_INPUT_INVALID);

    point.time = libinput_event_pointer_get_time_usec(data);
    point.absolute.x = libinput_event_pointer_get_absolute_x_transformed(data,
                                                                         DEF_SCREEN_MAX_WIDTH);
    point.absolute.y = libinput_event_pointer_get_absolute_y_transformed(data,
                                                                         DEF_SCREEN_MAX_HEIGHT);
    struct EventPointer absPointer = windowSwitch.GetEventPointer();
    absPointer.absolute.x = point.absolute.x;
    absPointer.absolute.y = point.absolute.y;
    windowSwitch.SetPointerByAbsMotion(absPointer);
}

int32_t EventPackage::PackagePointerEventByButton(libinput_event& event,
                                                  EventPointer& point, WindowSwitch& windowSwitch)
{
    auto data = libinput_event_get_pointer_event(&event);
    CHKR(data, NULL_POINTER, RET_ERR);
    point.time = libinput_event_pointer_get_time_usec(data);
    point.button = libinput_event_pointer_get_button(data);
    point.seat_button_count = libinput_event_pointer_get_seat_button_count(data);
    if (libinput_event_pointer_get_button_state(data) == 0) {
        point.state = BUTTON_STATE_RELEASED;
    } else {
        point.state = BUTTON_STATE_PRESSED;
    }
    // Ignore button events that are not seat wide state changes.
    if (point.state == BUTTON_STATE_PRESSED && point.seat_button_count != SEAT_BUTTON_OR_KEY_COUNT_ONE) {
        return MULTIDEVICE_SAME_EVENT_FAIL;
    }
    if (point.state == BUTTON_STATE_RELEASED && point.seat_button_count != SEAT_BUTTON_OR_KEY_COUNT_ZERO) {
        return MULTIDEVICE_SAME_EVENT_FAIL;
    }
    struct EventPointer absPointer = windowSwitch.GetEventPointer();
    absPointer.button = point.button;
    absPointer.seat_button_count = point.seat_button_count;
    absPointer.state = point.state;
    if (point.state == BUTTON_STATE_PRESSED && point.button == BTN_LEFT) {
        absPointer.deviceType = point.deviceType;
        absPointer.deviceId = point.deviceId;
        CHKR(EOK == memcpy_s(absPointer.deviceName, sizeof(absPointer.deviceName),
             point.deviceName, sizeof(point.deviceName)), MEMCPY_SEC_FUN_FAIL, RET_ERR);
        CHKR(EOK == memcpy_s(absPointer.devicePhys, sizeof(absPointer.devicePhys),
             point.devicePhys, sizeof(point.devicePhys)), MEMCPY_SEC_FUN_FAIL, RET_ERR);
    }
    windowSwitch.SetPointerByButton(absPointer);
    return RET_OK;
}

void EventPackage::PackagePointerEventByAxis(libinput_event& event,
                                             EventPointer& point, WindowSwitch& windowSwitch)
{
    auto data = libinput_event_get_pointer_event(&event);
    CHK(data != nullptr, PARAM_INPUT_INVALID);

    point.time = libinput_event_pointer_get_time_usec(data);
    switch (libinput_event_pointer_get_axis_source(data)) {
        case LIBINPUT_POINTER_AXIS_SOURCE_WHEEL: {
            point.source = POINTER_AXIS_SOURCE_WHEEL;
            break;
        }
        case LIBINPUT_POINTER_AXIS_SOURCE_FINGER: {
            point.source = POINTER_AXIS_SOURCE_FINGER;
            break;
        }
        case LIBINPUT_POINTER_AXIS_SOURCE_CONTINUOUS: {
            point.source = POINTER_AXIS_SOURCE_CONTINUOUS;
            break;
        }
        case LIBINPUT_POINTER_AXIS_SOURCE_WHEEL_TILT: {
            point.source = POINTER_AXIS_SOURCE_WHEEL_TILT;
            break;
        }
        default: {
            break;
        }
    }
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
        point.axes = POINTER_AXIS_SCROLL_VERTICAL;
        point.delta.y = libinput_event_pointer_get_axis_value(data,
                                                              LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
        point.discrete.y = libinput_event_pointer_get_axis_value_discrete(data,
                                                                          LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
    }
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
        point.axes = POINTER_AXIS_SCROLL_HORIZONTAL;
        point.delta.x = libinput_event_pointer_get_axis_value(data,
                                                              LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
        point.discrete.x = libinput_event_pointer_get_axis_value_discrete(data,
                                                                          LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
    }
}

int32_t EventPackage::PackageJoyStickAxisEvent(libinput_event& event,
    EventJoyStickAxis& eventJoyStickAxis, UDSServer& udsServer)
{
    auto joyEvent = libinput_event_get_joystick_axis_event(&event);
    CHKR(joyEvent, NULL_POINTER, RET_ERR);
    auto ret = PackageEventDeviceInfo<EventJoyStickAxis>(event, eventJoyStickAxis, udsServer);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    eventJoyStickAxis.time = libinput_event_get_joystick_axis_time(joyEvent);
    struct {
        const std::string name;
        JOYSTICK_AXIS_SOURCE axis;
        struct EventJoyStickAxisAbsInfo& absInfo;
    } supportAxisInfos[] = {
        {"ABS_X", JOYSTICK_AXIS_SOURCE_ABS_X, eventJoyStickAxis.abs_x},
        {"ABS_Y", JOYSTICK_AXIS_SOURCE_ABS_Y, eventJoyStickAxis.abs_y},
        {"ABS_Z", JOYSTICK_AXIS_SOURCE_ABS_Z, eventJoyStickAxis.abs_z},
        {"ABS_RX", JOYSTICK_AXIS_SOURCE_ABS_RX, eventJoyStickAxis.abs_rx},
        {"ABS_RY", JOYSTICK_AXIS_SOURCE_ABS_RY, eventJoyStickAxis.abs_ry},
        {"ABS_RZ", JOYSTICK_AXIS_SOURCE_ABS_RZ, eventJoyStickAxis.abs_rz},
        {"ABS_THROTTLE", JOYSTICK_AXIS_SOURCE_ABS_THROTTLE, eventJoyStickAxis.abs_throttle},
        {"ABS_HAT0X", JOYSTICK_AXIS_SOURCE_ABS_HAT0X, eventJoyStickAxis.abs_hat0x},
        {"ABS_HAT0Y", JOYSTICK_AXIS_SOURCE_ABS_HAT0Y, eventJoyStickAxis.abs_hat0y},
    };
    for (auto& temp : supportAxisInfos) {
        libinput_joystick_axis_source axis = static_cast<libinput_joystick_axis_source>(temp.axis);
        if (!libinput_event_get_joystick_axis_value_is_changed(joyEvent, axis)) {
            continue;
        }
        auto pAbsInfo = libinput_event_get_joystick_axis_abs_info(joyEvent, axis);
        if (pAbsInfo != nullptr) {
            FillEventJoyStickAxisAbsInfo(temp.absInfo, *pAbsInfo);
        }
    }
    return RET_OK;
}

int32_t EventPackage::PackageTouchEvent(multimodal_libinput_event &ev,
    EventTouch& touch, WindowSwitch& windowSwitch, UDSServer& udsServer)
{
    auto type = libinput_event_get_type(ev.event);
    if (type == LIBINPUT_EVENT_TOUCH_CANCEL || type == LIBINPUT_EVENT_TOUCH_FRAME) {
        return UNKNOWN_EVENT_PKG_FAIL;
    }
    auto ret = PackageEventDeviceInfo<EventTouch>(*ev.event, touch, udsServer);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    auto data = libinput_event_get_touch_event(ev.event);
    CHKR(data, NULL_POINTER, RET_ERR);
    touch.time = libinput_event_touch_get_time_usec(data);
    touch.slot = libinput_event_touch_get_slot(data);
    touch.seat_slot = libinput_event_touch_get_seat_slot(data);
    touch.pressure = libinput_event_get_touch_pressure(ev.event);

    switch (type) {
        case LIBINPUT_EVENT_TOUCH_DOWN: {
            auto uData = static_cast<multimodal_input_pointer_data *>(ev.userdata);
            CHKR(uData, NULL_POINTER, RET_ERR);
            auto touchSurfaceInfo = WinMgr->GetTouchSurfaceInfo(uData->x, uData->y);
            CHKR(touchSurfaceInfo, NULL_POINTER, RET_ERR);
            WinMgr->SetTouchFocusSurfaceId(touchSurfaceInfo->surfaceId);
            touch.point.x = uData->sx;
            touch.point.y = uData->sy;
            MMI_LOGF("TouchDown:[x=%{public}d, y=%{public}d, sx=%{public}d, sy=%{public}d]",
                     uData->x, uData->y, uData->sx, uData->sy);
            break;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
            touch.point.x = 0;
            touch.point.y = 0;
            break;
        }
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            auto uData = static_cast<multimodal_input_pointer_data *>(ev.userdata);
            CHKR(uData, NULL_POINTER, RET_ERR);
            touch.point.x = uData->sx;
            touch.point.y = uData->sy;
            MMI_LOGF("TouchMotion: [x=%{public}d, y=%{public}d, sx=%{public}d, sy=%{public}d]",
                     uData->x, uData->y, uData->sx, uData->sy);
            break;
        }
        default: {
            break;
        }
    }
    return RET_OK;
}

int32_t EventPackage::PackagePointerEvent(multimodal_libinput_event &ev,
    EventPointer& point, WindowSwitch& windowSwitch, UDSServer& udsServer)
{
    auto type = libinput_event_get_type(ev.event);
    auto rDevRet = PackageEventDeviceInfo<EventPointer>(*ev.event, point, udsServer);
    int32_t ret = 0;
    if (rDevRet != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", rDevRet, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    switch (type) {
        case LIBINPUT_EVENT_POINTER_MOTION: {
            auto uData = static_cast<multimodal_input_pointer_data *>(ev.userdata);
            CHKR(uData, NULL_POINTER, RET_ERR);
            PackagePointerEventByMotion(*ev.event, point, windowSwitch);
            point.absolute.x = uData->sx;
            point.absolute.y = uData->sy;
            MMI_LOGF("PointerMotion: [x=%{public}d, y=%{public}d, sx=%{public}d, sy=%{public}d]",
                     uData->x, uData->y, uData->sx, uData->sy);
            break;
        }
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE: {
            PackagePointerEventByMotionAbs(*ev.event, point, windowSwitch);
            break;
        }
        case LIBINPUT_EVENT_POINTER_BUTTON: {
            auto uData = static_cast<multimodal_input_pointer_data *>(ev.userdata);
            CHKR(uData, NULL_POINTER, RET_ERR);
            PackagePointerEventByButton(*ev.event, point, windowSwitch);
            if (point.state == BUTTON_STATE_PRESSED) {
                auto touchSurfaceInfo = WinMgr->GetTouchSurfaceInfo(uData->x, uData->y);
                CHKR(touchSurfaceInfo, NULL_POINTER, RET_ERR);
                WinMgr->SetTouchFocusSurfaceId(touchSurfaceInfo->surfaceId);
            }
            point.absolute.x = uData->sx;
            point.absolute.y = uData->sy;
            MMI_LOGF("PointerButton: [x=%{public}d, y=%{public}d, sx=%{public}d, sy=%{public}d]",
                     uData->x, uData->y, uData->sx, uData->sy);
            break;
        }
        case LIBINPUT_EVENT_POINTER_AXIS: {
            PackagePointerEventByAxis(*ev.event, point, windowSwitch);
            break;
        }
        default: {
            break;
        }
    }
    return ret;
}

int32_t OHOS::MMI::EventPackage::PackageGestureEvent(libinput_event& event, EventGesture& gesture, UDSServer& udsServer)
{
    auto data = libinput_event_get_gesture_event(&event);
    CHKR(data, NULL_POINTER, RET_ERR);
    auto type = libinput_event_get_type(&event);
    auto ret = PackageEventDeviceInfo<EventGesture>(event, gesture, udsServer);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    gesture.time = libinput_event_gesture_get_time_usec(data);
    gesture.fingerCount = libinput_event_gesture_get_finger_count(data);
    switch (type) {
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE: {
            gesture.delta.x = libinput_event_gesture_get_dx(data);
            gesture.delta.y = libinput_event_gesture_get_dy(data);
            gesture.deltaUnaccel.x = libinput_event_gesture_get_dx_unaccelerated(data);
            gesture.deltaUnaccel.y = libinput_event_gesture_get_dy_unaccelerated(data);
            sloted_coords_info* pSoltTouches = libinput_event_gesture_get_solt_touches(data);
            CHKR(pSoltTouches, NULL_POINTER, RET_ERR);
            FillEventSlotedCoordsInfo(gesture.soltTouches, *pSoltTouches);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_END: {
            gesture.cancelled = libinput_event_gesture_get_cancelled(data);
            break;
        }
        default: {
            break;
        }
    }
    return RET_OK;
}

int32_t EventPackage::PackageDeviceManageEvent(libinput_event& event, DeviceManage& deviceManage, UDSServer& udsServer)
{
    auto ret = PackageEventDeviceInfo<DeviceManage>(event, deviceManage, udsServer);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    return RET_OK;
}

int32_t EventPackage::PackageKeyEvent(libinput_event& event, EventKeyboard& key, UDSServer& udsServer)
{
    auto data = libinput_event_get_keyboard_event(&event);
    CHKR(data, NULL_POINTER, RET_ERR);
    key.key = libinput_event_keyboard_get_key(data);
    auto ret = PackageEventDeviceInfo<EventKeyboard>(event, key, udsServer);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    if (libinput_event_keyboard_get_key_state(data) == 0) {
        key.state = KEY_STATE_RELEASED;
    } else {
        key.state = KEY_STATE_PRESSED;
    }
    key.seat_key_count = libinput_event_keyboard_get_seat_key_count(data);
    key.time = libinput_event_keyboard_get_time_usec(data);
    // Ignore key events that are not seat wide state changes.
    if (key.state == KEY_STATE_PRESSED && key.seat_key_count != SEAT_BUTTON_OR_KEY_COUNT_ONE) {
        return MULTIDEVICE_SAME_EVENT_FAIL;
    }
    if (key.state == KEY_STATE_RELEASED && key.seat_key_count != SEAT_BUTTON_OR_KEY_COUNT_ZERO) {
        return MULTIDEVICE_SAME_EVENT_FAIL;
    }
    return RET_OK;
}
}
}