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
namespace {
    const std::string VIRTUAL_KEYBOARD = "virtual_keyboard";
    constexpr uint32_t SEAT_KEY_COUNT_ONE = 1;
    constexpr uint32_t SEAT_KEY_COUNT_ZERO = 0;
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventPackage" };

    void FillEventJoyStickAxisAbsInfo(EventJoyStickAxisAbsInfo& l, const libinput_event_joystick_axis_abs_info& r)
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

    void FillEventSlotedCoordsInfo(SlotedCoordsInfo& l, const sloted_coords_info& r)
    {
        l.activeCount = r.active_count;
        for (int i = 0; i < MAX_SOLTED_COORDS_NUMS; i++) {
            l.coords[i].isActive = r.coords[i].is_active;
            l.coords[i].x = r.coords[i].x;
            l.coords[i].y = r.coords[i].y;
        }
    }

    DEVICE_TYPE GetDeviceType(struct libinput_device* device)
    {
        CHKPR(device, ERROR_NULL_POINTER, DEVICE_TYPE_UNKNOWN);
        enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
        if (udevTags & EVDEV_UDEV_TAG_JOYSTICK) {
            return DEVICE_TYPE_JOYSTICK;
        } else if (udevTags & EVDEV_UDEV_TAG_KEYBOARD) {
            return DEVICE_TYPE_KEYBOARD;
        } else if (udevTags & (EVDEV_UDEV_TAG_MOUSE | EVDEV_UDEV_TAG_TRACKBALL | EVDEV_UDEV_TAG_POINTINGSTICK)) {
            return DEVICE_TYPE_MOUSE;
        } else if (udevTags & EVDEV_UDEV_TAG_TOUCHSCREEN) {
            return DEVICE_TYPE_TOUCH_PANEL;
        } else if (udevTags & (EVDEV_UDEV_TAG_TOUCHPAD | EVDEV_UDEV_TAG_TABLET_PAD)) {
            return DEVICE_TYPE_TOUCHPAD;
        } else if (udevTags & EVDEV_UDEV_TAG_TABLET) {
            return DEVICE_TYPE_STYLUS;
        } else {
            MMI_LOGW("Unknown device type");
            return DEVICE_TYPE_UNKNOWN;
        }
    }
}

EventPackage::EventPackage()
{
}

EventPackage::~EventPackage()
{
}

template<class EventType>
int32_t EventPackage::PackageEventDeviceInfo(libinput_event *event, EventType& data)
{
    CHKPR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto device = libinput_event_get_device(event);
    CHKR(device, ERROR_NULL_POINTER, LIBINPUT_DEV_EMPTY);
    auto type = libinput_event_get_type(event);
    data.eventType = type;
    data.deviceType = GetDeviceType(device);
    auto name = libinput_device_get_name(device);
    CHKR(name, ERROR_NULL_POINTER, RET_ERR);
    int32_t ret = memcpy_s(data.deviceName, sizeof(data.deviceName), name, MAX_DEVICENAME);
    CHKR(ret == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
    const std::string uuid = GetUUid();
    ret = memcpy_s(data.uuid, MAX_UUIDSIZE, uuid.c_str(), uuid.size());
    CHKR(ret == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
#ifdef OHOS_BUILD_HDF
    ret = memcpy_s(data.physical, MAX_DEVICENAME, data.deviceName, MAX_DEVICENAME);
    CHKR(ret == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
#else
    const char* physWhole = libinput_device_get_phys(device);
    if (physWhole == nullptr) {
        ret = memcpy_s(data.physical, sizeof(data.physical), data.deviceName,
                       sizeof(data.deviceName));
        CHKR(ret == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
    } else {
        std::string s(physWhole);
        std::string phys = s.substr(0, s.rfind('/'));
        CHKR(!phys.empty(), ERROR_NULL_POINTER, RET_ERR);
        ret = memcpy_s(data.physical, sizeof(data.physical), phys.c_str(), MAX_DEVICENAME);
        CHKR(ret == EOK, MEMCPY_SEC_FUN_FAIL, RET_ERR);
    }
#endif
    std::string physical(data.physical);
    if (type == LIBINPUT_EVENT_DEVICE_REMOVED) {
        DevRegister->DeleteDeviceInfo(physical);
        MMI_LOGI("The libinput event device is removed, EventType:%{public}d", type);
        return RET_OK;
    }
    uint32_t deviceId;
    if (DevRegister->FindDeviceId(physical, deviceId)) {
        data.deviceId = deviceId;
    } else {
        deviceId = DevRegister->AddDeviceInfo(physical);
        CHKR(deviceId, ADD_DEVICE_INFO_CALL_FAIL, RET_ERR);
        data.deviceId = deviceId;
    }
    return RET_OK;
}

int32_t EventPackage::PackageTabletToolOtherParams(libinput_event *event, EventTabletTool& tableTool)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto type = libinput_event_get_type(event);
    auto data = libinput_event_get_tablet_tool_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);
    auto tool = libinput_event_tablet_tool_get_tool(data);
    CHKR(tool, ERROR_NULL_POINTER, RET_ERR);
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
        if (tableTool.state == BUTTON_STATE_PRESSED && tableTool.seat_button_count != 1) {
            return MULTIDEVICE_SAME_EVENT_MARK;
        }
        if (tableTool.state == BUTTON_STATE_RELEASED && tableTool.seat_button_count != 0) {
            return MULTIDEVICE_SAME_EVENT_MARK;
        }
    }
    return RET_OK;
}
void EventPackage::PackageTabletToolTypeParam(libinput_event *event, EventTabletTool& tableTool)
{
    CHK(event, PARAM_INPUT_INVALID);
    auto data = libinput_event_get_tablet_tool_event(event);
    CHK(data != nullptr, ERROR_NULL_POINTER);
    auto tool = libinput_event_tablet_tool_get_tool(data);
    CHK(tool != nullptr, ERROR_NULL_POINTER);
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

int32_t EventPackage::PackageTabletToolEvent(libinput_event *event, EventTabletTool& tableTool)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    const uint32_t stylusButton1KeyCode = 331;
    const uint32_t stylusButton2KeyCode = 332;
    const uint32_t stylusButton1Value = 1;
    const uint32_t stylusButton2Value = 2;
    auto data = libinput_event_get_tablet_tool_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);
    auto tool = libinput_event_tablet_tool_get_tool(data);
    CHKR(tool, ERROR_NULL_POINTER, RET_ERR);
    auto rDevRet = PackageEventDeviceInfo<EventTabletTool>(event, tableTool);
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
void EventPackage::PackageTabletPadOtherParams(libinput_event *event, EventTabletPad& tabletPad)
{
    CHK(event, PARAM_INPUT_INVALID);
    auto data = libinput_event_get_tablet_pad_event(event);
    CHK(data != nullptr, ERROR_NULL_POINTER);
    auto type = libinput_event_get_type(event);
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

int32_t EventPackage::PackageTabletPadEvent(libinput_event *event, EventTabletPad& tabletPad)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto data = libinput_event_get_tablet_pad_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);
    tabletPad.mode = libinput_event_tablet_pad_get_mode(data);
    tabletPad.time = libinput_event_tablet_pad_get_time_usec(data);
    auto ret = PackageEventDeviceInfo<EventTabletPad>(event, tabletPad);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    PackageTabletPadOtherParams(event, tabletPad);
    return RET_OK;
}

int32_t EventPackage::PackageTabletPadKeyEvent(libinput_event *event, EventKeyboard& key)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto data = libinput_event_get_tablet_pad_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);
    auto type = libinput_event_get_type(event);
    key.time = libinput_event_tablet_pad_get_time_usec(data);
    auto ret = PackageEventDeviceInfo<EventKeyboard>(event, key);
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
    if (key.state == KEY_STATE_PRESSED && key.seat_key_count != 1) {
        return MULTIDEVICE_SAME_EVENT_MARK;
    }
    if (key.state == KEY_STATE_RELEASED && key.seat_key_count != 0) {
        return MULTIDEVICE_SAME_EVENT_MARK;
    }
    return RET_OK;
}

int32_t EventPackage::PackageJoyStickKeyEvent(libinput_event *event, EventKeyboard& key)
{
    CHKPR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto data = libinput_event_get_joystick_pointer_button_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);
    key.time = libinput_event_joystick_button_time(data);
    key.key = libinput_event_joystick_button_get_key(data);
    auto ret = PackageEventDeviceInfo<EventKeyboard>(event, key);
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

int32_t EventPackage::PackagePointerEventByMotion(libinput_event *event, EventPointer& point)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto data = libinput_event_get_pointer_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);

    point.time = libinput_event_pointer_get_time_usec(data);
    point.delta.x = libinput_event_pointer_get_dx(data);
    point.delta.y = libinput_event_pointer_get_dy(data);
    point.delta_raw.x = libinput_event_pointer_get_dx_unaccelerated(data);
    point.delta_raw.y = libinput_event_pointer_get_dy_unaccelerated(data);
    return RET_OK;
}

int32_t EventPackage::PackagePointerEventByMotionAbs(libinput_event *event, EventPointer& point)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto data = libinput_event_get_pointer_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);

    point.time = libinput_event_pointer_get_time_usec(data);
    point.absolute.x = libinput_event_pointer_get_absolute_x_transformed(data,
                                                                         DEF_SCREEN_MAX_WIDTH);
    point.absolute.y = libinput_event_pointer_get_absolute_y_transformed(data,
                                                                         DEF_SCREEN_MAX_HEIGHT);
    return RET_OK;
}

int32_t EventPackage::PackagePointerEventByButton(libinput_event *event, EventPointer& point)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto data = libinput_event_get_pointer_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);

    point.time = libinput_event_pointer_get_time_usec(data);
    point.button = libinput_event_pointer_get_button(data);
    point.seat_button_count = libinput_event_pointer_get_seat_button_count(data);
    if (libinput_event_pointer_get_button_state(data) == LIBINPUT_BUTTON_STATE_RELEASED) {
        point.state = BUTTON_STATE_RELEASED;
    } else {
        point.state = BUTTON_STATE_PRESSED;
    }
    // Ignore button events that are not seat wide state changes.
    if ((point.state == BUTTON_STATE_PRESSED) && (point.seat_button_count != 1)) {
        return MULTIDEVICE_SAME_EVENT_MARK;
    }
    if ((point.state == BUTTON_STATE_RELEASED) && (point.seat_button_count != 0)) {
        return MULTIDEVICE_SAME_EVENT_MARK;
    }
    return RET_OK;
}

int32_t EventPackage::PackagePointerEventByAxis(libinput_event *event, EventPointer& point)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto data = libinput_event_get_pointer_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);

    point.time = libinput_event_pointer_get_time_usec(data);
    auto axisSource = libinput_event_pointer_get_axis_source(data);
    switch (axisSource) {
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
            MMI_LOGW("Unknown event source of pointer, PointerAxisSource:%{puiblic}d",
                     axisSource);
            break;
        }
    }
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
        point.axis = POINTER_AXIS_SCROLL_VERTICAL;
        point.delta.y = libinput_event_pointer_get_axis_value(data,
                                                              LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
        point.discrete.y = libinput_event_pointer_get_axis_value_discrete(data,
                                                                          LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
    }
    if (libinput_event_pointer_has_axis(data, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
        point.axis = POINTER_AXIS_SCROLL_HORIZONTAL;
        point.delta.x = libinput_event_pointer_get_axis_value(data,
                                                              LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
        point.discrete.x = libinput_event_pointer_get_axis_value_discrete(data,
                                                                          LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
    }
    return RET_OK;
}

int32_t EventPackage::PackageJoyStickAxisEvent(libinput_event *event, EventJoyStickAxis& eventJoyStickAxis)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto joyEvent = libinput_event_get_joystick_axis_event(event);
    CHKR(joyEvent, ERROR_NULL_POINTER, RET_ERR);
    auto ret = PackageEventDeviceInfo<EventJoyStickAxis>(event, eventJoyStickAxis);
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

void EventPackage::PackageTouchEventByType(int32_t type, struct libinput_event_touch *data, EventTouch& touch)
{
    switch (type) {
        case LIBINPUT_EVENT_TOUCH_DOWN: {
            touch.point.x = libinput_event_touch_get_x(data);
            touch.point.y = libinput_event_touch_get_y(data);
#ifdef OHOS_WESTEN_MODEL
            auto touchSurfaceInfo = WinMgr->GetTouchSurfaceInfo(touch.point.x, touch.point.y);
            CHKR(touchSurfaceInfo, ERROR_NULL_POINTER, RET_ERR);
            WinMgr->SetTouchFocusSurfaceId(touchSurfaceInfo->surfaceId);
            WinMgr->TransfromToSurfaceCoordinate(touch.point.x, touch.point.y, *touchSurfaceInfo, true);
#endif
            break;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
#ifdef OHOS_WESTEN_MODEL
            MMIRegEvent->GetTouchInfoByTouchId(std::make_pair(touch.deviceId, touch.seatSlot), touch);
#endif
            touch.time = libinput_event_touch_get_time_usec(data);
            touch.eventType = LIBINPUT_EVENT_TOUCH_UP;
            break;
        }
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            touch.point.x = libinput_event_touch_get_x(data);
            touch.point.y = libinput_event_touch_get_y(data);
#ifdef OHOS_WESTEN_MODEL
            auto touchSurfaceId = WinMgr->GetTouchFocusSurfaceId();
            auto touchSurfaceInfo = WinMgr->GetSurfaceInfo(touchSurfaceId);
            CHKR(touchSurfaceInfo, ERROR_NULL_POINTER, RET_ERR);
            WinMgr->TransfromToSurfaceCoordinate(touch.point.x, touch.point.y, *touchSurfaceInfo);
#endif
            break;
        }
        default: {
            MMI_LOGW("Unknown event type of touch, touchType:%{public}d", type);
            break;
        }
    }
    return;
}

int32_t EventPackage::PackageTouchEvent(libinput_event *event, EventTouch& touch)
{
    CHKPR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCH_CANCEL || type == LIBINPUT_EVENT_TOUCH_FRAME) {
        MMI_LOGT("This touch event is canceled type:%{public}d", type);
        return UNKNOWN_EVENT_PKG_FAIL;
    }
    auto ret = PackageEventDeviceInfo<EventTouch>(event, touch);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed, ret:%{public}d,errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    auto data = libinput_event_get_touch_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);
    touch.time = libinput_event_touch_get_time_usec(data);
    touch.slot = libinput_event_touch_get_slot(data);
    touch.seatSlot = libinput_event_touch_get_seat_slot(data);
    touch.pressure = libinput_event_get_touch_pressure(event);
    
    PackageTouchEventByType(type, data, touch);
    /* switch (type) {
        case LIBINPUT_EVENT_TOUCH_DOWN: {
            touch.point.x = libinput_event_touch_get_x(data);
            touch.point.y = libinput_event_touch_get_y(data);
#ifdef OHOS_WESTEN_MODEL
            auto touchSurfaceInfo = WinMgr->GetTouchSurfaceInfo(touch.point.x, touch.point.y);
            CHKR(touchSurfaceInfo, ERROR_NULL_POINTER, RET_ERR);
            WinMgr->SetTouchFocusSurfaceId(touchSurfaceInfo->surfaceId);
            WinMgr->TransfromToSurfaceCoordinate(touch.point.x, touch.point.y, *touchSurfaceInfo, true);
#endif
            break;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
#ifdef OHOS_WESTEN_MODEL
            MMIRegEvent->GetTouchInfo(std::make_pair(touch.deviceId, touch.seatSlot), touch);
#endif
            touch.time = libinput_event_touch_get_time_usec(data);
            touch.eventType = LIBINPUT_EVENT_TOUCH_UP;
            break;
        }
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            touch.point.x = libinput_event_touch_get_x(data);
            touch.point.y = libinput_event_touch_get_y(data);
#ifdef OHOS_WESTEN_MODEL
            auto touchSurfaceId = WinMgr->GetTouchFocusSurfaceId();
            auto touchSurfaceInfo = WinMgr->GetSurfaceInfo(touchSurfaceId);
            CHKR(touchSurfaceInfo, ERROR_NULL_POINTER, RET_ERR);
            WinMgr->TransfromToSurfaceCoordinate(touch.point.x, touch.point.y, *touchSurfaceInfo);
#endif
            break;
        }
        default: {
            break;
        }
    } */
    return RET_OK;
}

int32_t EventPackage::PackagePointerEvent(libinput_event *event, EventPointer& point)
{
    CHKPR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto rDevRet = PackageEventDeviceInfo<EventPointer>(event, point);
    if (rDevRet != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", rDevRet, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    int32_t ret = RET_OK;
    auto type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_POINTER_MOTION: {
            ret = PackagePointerEventByMotion(event, point);
            break;
        }
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE: {
            ret = PackagePointerEventByMotionAbs(event, point);
            break;
        }
        case LIBINPUT_EVENT_POINTER_BUTTON: {
            ret = PackagePointerEventByButton(event, point);
            break;
        }
        case LIBINPUT_EVENT_POINTER_AXIS: {
            ret = PackagePointerEventByAxis(event, point);
            break;
        }
        default: {
            ret = RET_ERR;
            MMI_LOGW("Unknown event type of pointer, PointerEventType:%{public}d", type);
            break;
        }
    }
    return ret;
}

int32_t EventPackage::PackageGestureEvent(libinput_event *event, EventGesture& gesture)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto data = libinput_event_get_gesture_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);
    auto ret = PackageEventDeviceInfo<EventGesture>(event, gesture);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed, ret:%{public}d, errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    gesture.time = libinput_event_gesture_get_time_usec(data);
    gesture.fingerCount = libinput_event_gesture_get_finger_count(data);
    auto type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_GESTURE_PINCH_BEGIN: {
            gesture.pointerEventType = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_UPDATE: {
            gesture.pointerEventType = PointerEvent::POINTER_ACTION_AXIS_UPDATE;
            gesture.scale = libinput_event_gesture_get_scale(data);
            gesture.angle = libinput_event_gesture_get_angle_delta(data);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_END: {
            gesture.pointerEventType = PointerEvent::POINTER_ACTION_AXIS_END;
            gesture.scale = libinput_event_gesture_get_scale(data);
            gesture.angle = libinput_event_gesture_get_angle_delta(data);
            gesture.cancelled = libinput_event_gesture_get_cancelled(data);
            break;
        }
        /* Third, it refers to the use of requirements, and the code is reserved */
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE: {
            MMI_LOGI("Three finger slide event update");
            gesture.delta.x = libinput_event_gesture_get_dx(data);
            gesture.delta.y = libinput_event_gesture_get_dy(data);
            gesture.deltaUnaccel.x = libinput_event_gesture_get_dx_unaccelerated(data);
            gesture.deltaUnaccel.y = libinput_event_gesture_get_dy_unaccelerated(data);
            sloted_coords_info* pSoltTouches = libinput_event_gesture_get_solt_touches(data);
            CHKR(pSoltTouches, ERROR_NULL_POINTER, RET_ERR);
            FillEventSlotedCoordsInfo(gesture.soltTouches, *pSoltTouches);
            break;
        }
        /* Third, it refers to the use of requirements, and the code is reserved */
        case LIBINPUT_EVENT_GESTURE_SWIPE_END: {
            MMI_LOGI("Three finger slide event end");
            gesture.cancelled = libinput_event_gesture_get_cancelled(data);
            break;
        }
        default: {
            MMI_LOGE("Event gesture type:%{public}d", type);
            break;
        }
    }
    return RET_OK;
}

int32_t EventPackage::PackageDeviceManageEvent(libinput_event *event, DeviceManage& deviceManage)
{
    CHKR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto ret = PackageEventDeviceInfo<DeviceManage>(event, deviceManage);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    return RET_OK;
}

int32_t EventPackage::PackageKeyEvent(libinput_event *event, EventKeyboard& key)
{
    CHKPR(event, PARAM_INPUT_INVALID, RET_ERR);
    auto data = libinput_event_get_keyboard_event(event);
    CHKPR(data, ERROR_NULL_POINTER, RET_ERR);
    key.key = libinput_event_keyboard_get_key(data);
    auto ret = PackageEventDeviceInfo<EventKeyboard>(event, key);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed. ret:%{public}d, errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
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
    if (key.state == KEY_STATE_PRESSED && key.seat_key_count != 1) {
        MMI_LOGD("The same button is pressed on multiple devices, state:%{puiblic}d", key.state);
        return MULTIDEVICE_SAME_EVENT_MARK;
    }
    if (key.state == KEY_STATE_RELEASED && key.seat_key_count != 0) {
        MMI_LOGD("Release the same button on multiple devices, state:%{puiblic}d", key.state);
        return MULTIDEVICE_SAME_EVENT_MARK;
    }
    return RET_OK;
}

int32_t EventPackage::PackageKeyEvent(libinput_event *event, std::shared_ptr<KeyEvent> kevnPtr)
{
    CHKPR(event, PARAM_INPUT_INVALID, RET_ERR);
    MMI_LOGD("PackageKeyEvent begin");
    CHKR(kevnPtr, ERROR_NULL_POINTER, RET_ERR);
    kevnPtr->UpdateId();
    EventKeyboard key = {};
    auto ret = PackageEventDeviceInfo<EventKeyboard>(event, key);
    if (ret != RET_OK) {
        MMI_LOGE("Device param package failed... ret:%{public}d errCode:%{public}d", ret, DEV_PARAM_PKG_FAIL);
        return DEV_PARAM_PKG_FAIL;
    }
    auto data = libinput_event_get_keyboard_event(event);
    CHKR(data, ERROR_NULL_POINTER, RET_ERR);
    // libinput key transformed into HOS key
    auto hosKey = KeyValueTransformationByInput(libinput_event_keyboard_get_key(data)); 

    int32_t deviceId = static_cast<int32_t>(key.deviceId);
    int32_t actionTime = static_cast<int64_t>(GetSysClockTime());
    int32_t keyCode = static_cast<int32_t>(hosKey.keyValueOfHos);
    int32_t keyAction = (libinput_event_keyboard_get_key_state(data) == 0) ?
        (KeyEvent::KEY_ACTION_UP) : (KeyEvent::KEY_ACTION_DOWN);
    int32_t actionStartTime = static_cast<int32_t>(libinput_event_keyboard_get_time_usec(data));

    kevnPtr->SetActionTime(actionTime);
    kevnPtr->SetAction(keyAction);
    kevnPtr->SetActionStartTime(actionStartTime);
    kevnPtr->SetDeviceId(deviceId);
    kevnPtr->SetKeyCode(keyCode);
    kevnPtr->SetKeyAction(keyAction);

    KeyEvent::KeyItem item;
    bool isKeyPressed = (libinput_event_keyboard_get_key_state(data) == 0) ? (false) : (true);
    if (isKeyPressed) {
        int32_t keyDownTime = actionStartTime;
        item.SetDownTime(keyDownTime);
    }
    item.SetKeyCode(keyCode);
    item.SetDeviceId(deviceId);
    item.SetPressed(isKeyPressed); 

    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        kevnPtr->AddPressedKeyItems(item);
    }
    if (keyAction == KeyEvent::KEY_ACTION_UP) {
        kevnPtr->RemoveReleasedKeyItems(item);
    }
    MMI_LOGD("PackageKeyEvent end");
    return RET_OK;
}

int32_t EventPackage::PackageVirtualKeyEvent(VirtualKey& event, EventKeyboard& key)
{
    const std::string uid = GetUUid();
    CHKR(EOK == memcpy_s(key.uuid, MAX_UUIDSIZE, uid.c_str(), uid.size()),
        MEMCPY_SEC_FUN_FAIL, RET_ERR);
    CHKR(EOK == memcpy_s(key.deviceName, MAX_UUIDSIZE, VIRTUAL_KEYBOARD.c_str(),
        VIRTUAL_KEYBOARD.size()), MEMCPY_SEC_FUN_FAIL, RET_ERR);
    key.time = event.keyDownDuration;
    key.key = event.keyCode;
    key.isIntercepted = event.isIntercepted;
    key.state = (enum KEY_STATE)event.isPressed;
    key.eventType = LIBINPUT_EVENT_KEYBOARD_KEY;
    key.deviceType = DEVICE_TYPE_VIRTUAL_KEYBOARD;
    key.unicode = 0;
    if (event.isPressed) {
        key.seat_key_count = SEAT_KEY_COUNT_ONE;
    } else {
        key.seat_key_count = SEAT_KEY_COUNT_ZERO;
    }
    return RET_OK;
}

int32_t EventPackage::KeyboardToKeyEvent(const EventKeyboard& key, std::shared_ptr<KeyEvent> keyEventPtr)
{
    CHKPR(keyEventPtr, ERROR_NULL_POINTER, RET_ERR);
    keyEventPtr->UpdateId();
    KeyEvent::KeyItem keyItem;
    int32_t actionTime = static_cast<int64_t>(GetSysClockTime());
    int32_t keyCode = static_cast<int32_t>(key.key);
    int32_t keyAction = (key.state == KEY_STATE_PRESSED) ?
        (KeyEvent::KEY_ACTION_DOWN) : (KeyEvent::KEY_ACTION_UP);
    int32_t deviceId = static_cast<int32_t>(key.deviceId);
    int32_t actionStartTime = static_cast<int32_t>(key.time);
    auto preAction = keyEventPtr->GetAction();
    if (preAction == KeyEvent::KEY_ACTION_UP) {
        auto preUpKeyItem = keyEventPtr->GetKeyItem();
        if (preUpKeyItem != nullptr) {
            keyEventPtr->RemoveReleasedKeyItems(*preUpKeyItem);
        } else {
            MMI_LOGE("preUpKeyItem is null");
        }
    }

    keyEventPtr->SetActionTime(actionStartTime);
    keyEventPtr->SetAction(keyAction);
    keyEventPtr->SetDeviceId(deviceId);

    keyEventPtr->SetKeyCode(keyCode);
    keyEventPtr->SetKeyAction(keyAction);

    if (keyEventPtr->GetPressedKeys().empty()) {
        keyEventPtr->SetActionStartTime(actionStartTime);
    }

    bool isKeyPressed = (key.state == KEY_STATE_PRESSED) ? (true) : (false);
    keyItem.SetDownTime(actionStartTime);
    keyItem.SetKeyCode(keyCode);
    keyItem.SetDeviceId(deviceId);
    keyItem.SetPressed(isKeyPressed);

    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        keyEventPtr->AddPressedKeyItems(keyItem);
    } else if (keyAction == KeyEvent::KEY_ACTION_UP) {
        auto pressedKeyItem = keyEventPtr->GetKeyItem(keyCode);
        if (pressedKeyItem != nullptr) {
            keyItem.SetDownTime(pressedKeyItem->GetDownTime());
        } else {
            MMI_LOGE("find pressed key failed, keyCode: %{public}d", keyCode);
        }
        keyEventPtr->RemoveReleasedKeyItems(keyItem);
        keyEventPtr->AddPressedKeyItems(keyItem);
    } else {
        // nothing to do.
    }
    return RET_OK;
}
}
}
