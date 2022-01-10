/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "mouse_event_handler.h"
#include <thread>
#include "input_windows_manager.h"
#include "libmmi_util.h"
#include "mouse_event.h"
#include "util.h"


static double g_coordinateX = 0;
static double g_coordinateY = 0;
static int32_t g_btnId = -1;
static bool g_isPressed = false;

namespace OHOS::MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MouseEventHandler"};
}
}

OHOS::MMI::MouseEventHandler::MouseEventHandler(int32_t eventType) : PointerEvent(eventType)
{
}

OHOS::MMI::MouseEventHandler::~MouseEventHandler()
{
}

void OHOS::MMI::MouseEventHandler::CalcMovedCoordinate(struct libinput_event_pointer& pointEventData)
{
    if (libinput_event_pointer_get_dx(&pointEventData) != 0) {
        g_coordinateX += libinput_event_pointer_get_dx(&pointEventData);
    }
    if (libinput_event_pointer_get_dy(&pointEventData) != 0) {
        g_coordinateY += libinput_event_pointer_get_dy(&pointEventData);
    }

    WinMgr->AdjustCoordinate(g_coordinateX, g_coordinateY);
    MMI_LOGI("g_coordinateX is : %{public}lf, g_coordinateY is : %{public}lf", g_coordinateX, g_coordinateY);
}

void OHOS::MMI::MouseEventHandler::SetMouseMotion(MouseInfo info, PointerEvent::PointerItem& pointerItem)
{
    this->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    this->SetButtonId(g_btnId);
    pointerItem.SetGlobalX(info.globleX);
    pointerItem.SetGlobalY(info.globleY);
    pointerItem.SetLocalX(info.localX);
    pointerItem.SetLocalY(info.localY);
    pointerItem.SetPressed(g_isPressed);
}

void OHOS::MMI::MouseEventHandler::SetMouseButon(PointerEvent::PointerItem& pointerItem,
                                                 struct libinput_event_pointer& pointEventData)
{
    bool isPressed = false;
    MouseInfo info = WinMgr->GetMouseInfo();

    if (libinput_event_pointer_get_button(&pointEventData) == LEFT_BUTTON) {
        this->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
        g_btnId = this->GetButtonId();
    } else if (libinput_event_pointer_get_button(&pointEventData) == RIGHT_BUTTON) {
        this->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);
        g_btnId = this->GetButtonId();
    } else if (libinput_event_pointer_get_button(&pointEventData) == MIDDLE_BUTTON) {
        this->SetButtonId(PointerEvent::MOUSE_BUTTON_MIDDLE);
        g_btnId = this->GetButtonId();
    } else {
        MMI_LOGW("PointerAction : %{public}d, unProces Button code : %{public}u",
        this->GetPointerAction(), libinput_event_pointer_get_button(&pointEventData));
    }
    if (libinput_event_pointer_get_button_state(&pointEventData) == LIBINPUT_BUTTON_STATE_RELEASED) {
        this->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
        isPressed = false;
        g_isPressed = isPressed;
        g_btnId = BUTTON_NONE;
    } else if (libinput_event_pointer_get_button_state(&pointEventData) == LIBINPUT_BUTTON_STATE_PRESSED) {
        this->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        this->SetButtonPressed(libinput_event_pointer_get_button(&pointEventData));
        isPressed = true;
        g_isPressed = isPressed;
    }

    pointerItem.SetPressed(isPressed);
    pointerItem.SetGlobalX(info.globleX);
    pointerItem.SetGlobalY(info.globleY);
    pointerItem.SetLocalX(info.localX);
    pointerItem.SetLocalY(info.localY);
}

void OHOS::MMI::MouseEventHandler::SetMouseAxis(struct libinput_event_pointer& pointEventData)
{
    double axisValue = 0;
    this->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);

    if (libinput_event_pointer_has_axis(&pointEventData, LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL)) {
        axisValue = libinput_event_pointer_get_axis_value(&pointEventData,
                                                          LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
        this->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (libinput_event_pointer_has_axis(&pointEventData, LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL)) {
        axisValue = libinput_event_pointer_get_axis_value(&pointEventData,
                                                          LIBINPUT_POINTER_AXIS_SCROLL_HORIZONTAL);
        this->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
}

void OHOS::MMI::MouseEventHandler::SetMouseData(libinput_event& event, int32_t deviceId)
{
    OHOS::MMI::PointerEvent::PointerItem pointerItem;
    struct libinput_event_pointer *pointEventData = nullptr;
    pointEventData = libinput_event_get_pointer_event(&event);
    uint64_t time = libinput_event_pointer_get_time_usec(pointEventData);
    int32_t type = libinput_event_get_type(&event);

    this->SetActionTime(static_cast<int32_t>(GetSysClockTime()));
    this->SetActionStartTime(static_cast<int32_t>(time));
    this->SetDeviceId(deviceId);
    this->SetPointerId(0);
    this->SetTargetDisplayId(0);
    this->SetTargetWindowId(-1);
    this->SetAgentWindowId(-1);
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(libinput_event_get_device(&event));
    if ((udevTags & EVDEV_UDEV_TAG_MOUSE) == EVDEV_UDEV_TAG_MOUSE) {
        this->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    } else if ((udevTags & EVDEV_UDEV_TAG_TOUCHPAD) == EVDEV_UDEV_TAG_TOUCHPAD) {
        this->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    } else {
        this->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    }
    if ((type == LIBINPUT_EVENT_POINTER_MOTION) || (type == LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE)) {
        CalcMovedCoordinate(*pointEventData);
        WinMgr->SetMouseInfo(g_coordinateX, g_coordinateY);
        MMI_LOGI("Change Coordinate : g_coordinateX = %{public}lf, g_coordinateY = %{public}lf",
                 g_coordinateX, g_coordinateY);
        MouseInfo info = WinMgr->GetMouseInfo();
        this->SetMouseMotion(info, pointerItem);
    } else if (type == LIBINPUT_EVENT_POINTER_BUTTON) {
        this->SetMouseButon(pointerItem, *pointEventData);
    } else if (type == LIBINPUT_EVENT_POINTER_AXIS) {
        this->SetMouseAxis(*pointEventData);
    }

    pointerItem.SetPointerId(0);
    pointerItem.SetDownTime(static_cast<int32_t>(time));
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);
    pointerItem.SetDeviceId(deviceId);
    this->AddPointerItem(pointerItem);
}

