/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "tablet_tool_tranform_processor.h"

#include <linux/input.h>

#include "device_state_manager.h"
#include "i_input_windows_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TabletToolTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t DEFAULT_POINTER_ID { 0 };
constexpr char CONFIG_NAME[] { "etc/input/input_product_config.json" };
constexpr double DEFAULT_PRECISION { 0.01 };
constexpr double CONSTANT_TWO { 2.0 };
} // namespace

TabletToolTransformProcessor::TabletToolTransformProcessor(int32_t deviceId)
    : deviceId_(deviceId)
{
    current_ = [this]() {
        DrawTouchGraphicIdle();
    };
}

std::shared_ptr<PointerEvent> TabletToolTransformProcessor::OnEvent(struct libinput_event* event)
{
    CHKPP(event);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
        CHKPP(pointerEvent_);
    }
    enum libinput_event_type type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_TABLET_TOOL_AXIS: {
            if (!OnTipMotion(event)) {
                MMI_HILOGE("OnTipMotion failed");
                return nullptr;
            }
            break;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY: {
            if (!OnTipProximity(event)) {
                MMI_HILOGE("OnTipProximity failed");
                return nullptr;
            }
            break;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_TIP: {
            if (!OnTip(event)) {
                MMI_HILOGE("OnTip failed");
                return nullptr;
            }
            break;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_BUTTON: {
            if (!OnToolButton(event)) {
                MMI_HILOGE("OnToolButton failed");
                return nullptr;
            }
            break;
        }
        default: {
            MMI_HILOGE("Unexpected event type");
            return nullptr;
        }
    }
    pointerEvent_->UpdateId();
    UpdateDeviceStateFromPointerEvent();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
    DrawTouchGraphic();
    return pointerEvent_;
}

void TabletToolTransformProcessor::OnDeviceRemoved()
{}

void TabletToolTransformProcessor::OnDeviceEnabled()
{
    MMI_HILOGI("Tablet tool[%{public}d] received enable notification", deviceId_);
}

void TabletToolTransformProcessor::OnDeviceDisabled()
{
    MMI_HILOGI("TabletTool[%{public}d] received disable notification", deviceId_);
    RecordActiveOperations();
    SendTipUpEvent();
    SendProximityOutEvent();
    SendButtonUpEvents();

    MMI_HILOGI("TabletTool[%{public}d] disabled, reset state data", deviceId_);
    pointerEvent_ = nullptr;
    isPressed_ = false;
    isProximity_ = false;
    calibration_ = std::nullopt;
    current_ = [this]() {
        DrawTouchGraphicIdle();
    };
}

void TabletToolTransformProcessor::RecordActiveOperations()
{
    if (pointerEvent_ == nullptr) {
        return;
    }

    auto pressedButtons = pointerEvent_->GetPressedButtons();
    if (pressedButtons.find(PointerEvent::MOUSE_BUTTON_RIGHT) != pressedButtons.cend()) {
        DEVICE_STATE_MGR->AddPressedButtons(deviceId_, std::set({ BTN_STYLUS }));
    }

    if (isProximity_) {
        DEVICE_STATE_MGR->SetProximity(deviceId_, true);
    }
}

void TabletToolTransformProcessor::SendTipUpEvent()
{
    if (!isPressed_ || (pointerEvent_ == nullptr)) {
        return;
    }

    auto time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem item {};
    if (!pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        MMI_HILOGE("GetPointerItem failed");
        return;
    }

    item.SetPressed(false);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    pointerEvent_->UpdateId();

    auto inputChannel = InputHandler->GetEventNormalizeHandler();
    if (inputChannel != nullptr) {
        LogTracer lt(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
        inputChannel->HandlePointerEvent(pointerEvent_);
        DrawTouchGraphic();
    }

    isPressed_ = false;
    MMI_HILOGI("Sent tip up event for tablet tool[%{public}d]", deviceId_);
}

void TabletToolTransformProcessor::SendProximityOutEvent()
{
    if (!isProximity_ || (pointerEvent_ == nullptr)) {
        return;
    }

    auto time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_PROXIMITY_OUT);

    PointerEvent::PointerItem item {};
    if (!pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        MMI_HILOGE("GetPointerItem failed");
        return;
    }

    item.SetPressed(false);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    pointerEvent_->UpdateId();

    auto inputChannel = InputHandler->GetEventNormalizeHandler();
    if (inputChannel != nullptr) {
        LogTracer lt(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
        inputChannel->HandlePointerEvent(pointerEvent_);
        DrawTouchGraphic();
    }

    isProximity_ = false;
    MMI_HILOGI("Sent proximity out event for tablet tool[%{public}d]", deviceId_);
}

void TabletToolTransformProcessor::SendButtonUpEvents()
{
    if (pointerEvent_ == nullptr) {
        return;
    }

    auto pressedButtons = pointerEvent_->GetPressedButtons();
    if (pressedButtons.empty()) {
        return;
    }

    auto time = GetSysClockTime();
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);

    for (auto buttonId : pressedButtons) {
        pointerEvent_->SetButtonId(buttonId);
        pointerEvent_->DeleteReleaseButton(buttonId);
        pointerEvent_->UpdateId();

        auto inputChannel = InputHandler->GetEventNormalizeHandler();
        if (inputChannel != nullptr) {
            LogTracer lt(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
            inputChannel->HandlePointerEvent(pointerEvent_);
        }

        MMI_HILOGI("Sent button up event for button[%{public}d]", buttonId);
    }
}

void TabletToolTransformProcessor::UpdateDeviceStateFromPointerEvent()
{
    if (pointerEvent_ == nullptr) {
        MMI_HILOGW("pointerEvent_ is null, cannot update device state");
        return;
    }

    switch (pointerEvent_->GetPointerAction()) {
        case PointerEvent::POINTER_ACTION_DOWN: {
            isPressed_ = true;
            isProximity_ = true;
            MMI_HILOGD("Tablet tool[%{public}d] pointer DOWN: isPressed=true, isProximity=true", deviceId_);
            break;
        }
        case PointerEvent::POINTER_ACTION_UP: {
            isPressed_ = false;
            MMI_HILOGD("Tablet tool[%{public}d] pointer UP: isPressed=false, isProximity=false", deviceId_);
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE:
        case PointerEvent::POINTER_ACTION_LEVITATE_MOVE: {
            if (!isProximity_) {
                isProximity_ = true;
                MMI_HILOGD("Tablet tool[%{public}d] pointer MOVE: isProximity=true", deviceId_);
            }
            break;
        }
        case PointerEvent::POINTER_ACTION_PROXIMITY_IN: {
            isProximity_ = true;
            MMI_HILOGD("Tablet tool[%{public}d] pointer PROXIMITY_IN: isProximity=true", deviceId_);
            break;
        }
        case PointerEvent::POINTER_ACTION_PROXIMITY_OUT: {
            isProximity_ = false;
            MMI_HILOGD("Tablet tool[%{public}d] pointer PROXIMITY_OUT: isProximity=false", deviceId_);
            break;
        }
        default: {
            break;
        }
    }

    MMI_HILOGD("Device state updated: isPressed=%{public}s, isProximity=%{public}s, pressedButtonsCount=%{public}zu",
        isPressed_ ? "true" : "false", isProximity_ ? "true" : "false", pointerEvent_->GetPressedButtons().size());
}

int32_t TabletToolTransformProcessor::GetToolType(struct libinput_event_tablet_tool* tabletEvent)
{
    int32_t toolType = libinput_event_tablet_tool_get_tool_type(tabletEvent);
    if (toolType != 0) {
        return PointerEvent::TOOL_TYPE_PEN;
    }
    auto tool = libinput_event_tablet_tool_get_tool(tabletEvent);
    CHKPR(tool, PointerEvent::TOOL_TYPE_PEN);
    int32_t type = libinput_tablet_tool_get_type(tool);
    switch (type) {
        case LIBINPUT_TABLET_TOOL_TYPE_PEN: {
            return PointerEvent::TOOL_TYPE_PEN;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_ERASER: {
            return PointerEvent::TOOL_TYPE_RUBBER;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_BRUSH: {
            return PointerEvent::TOOL_TYPE_BRUSH;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_PENCIL: {
            return PointerEvent::TOOL_TYPE_PENCIL;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_AIRBRUSH: {
            return PointerEvent::TOOL_TYPE_AIRBRUSH;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_MOUSE: {
            return PointerEvent::TOOL_TYPE_MOUSE;
        }
        case LIBINPUT_TABLET_TOOL_TYPE_LENS: {
            return PointerEvent::TOOL_TYPE_LENS;
        }
        default: {
            MMI_HILOGW("Invalid type");
            return PointerEvent::TOOL_TYPE_PEN;
        }
    }
}

bool TabletToolTransformProcessor::OnTip(struct libinput_event* event)
{
    CHKPF(event);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    CHKPF(tabletEvent);
    auto tipState = libinput_event_tablet_tool_get_tip_state(tabletEvent);
    bool ret = false;
    switch (tipState) {
        case LIBINPUT_TABLET_TOOL_TIP_DOWN: {
            ret = OnTipDown(tabletEvent);
            if (!ret) {
                MMI_HILOGE("OnTipDown failed");
            }
            break;
        }
        case LIBINPUT_TABLET_TOOL_TIP_UP: {
            ret = OnTipUp(tabletEvent);
            if (!ret) {
                MMI_HILOGE("OnTipUp failed");
            }
            break;
        }
        default: {
            MMI_HILOGE("Invalid tip state");
            break;
        }
    }
    return ret;
}

bool TabletToolTransformProcessor::OnTipDown(struct libinput_event_tablet_tool* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    int32_t targetDisplayId = -1;
    PhysicalCoordinate tCoord;
    PointerEvent::PointerItem item;
    if (pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        pointerEvent_->RemovePointerItem(DEFAULT_POINTER_ID);
    }
    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDeviceId(deviceId_);
    int32_t toolType = GetToolType(event);
    item.SetToolType(toolType);

    if (!CalculateCalibratedTipPoint(event, targetDisplayId, tCoord, item)) {
        MMI_HILOGE("CalculateCalibratedTipPoint failed");
        return false;
    }
    double tiltX = libinput_event_tablet_tool_get_tilt_x(event);
    double tiltY = libinput_event_tablet_tool_get_tilt_y(event);
    double pressure = libinput_event_tablet_tool_get_pressure(event);
    int32_t twist = libinput_event_tablet_tool_get_twist(event);

    uint64_t time = libinput_event_tablet_tool_get_time_usec(event);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetTargetDisplayId(targetDisplayId);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    item.SetDownTime(time);
    item.SetPressed(true);
    item.SetDisplayXPos(tCoord.x);
    item.SetDisplayYPos(tCoord.y);
    item.SetRawDisplayX(static_cast<int32_t>(tCoord.x));
    item.SetRawDisplayY(static_cast<int32_t>(tCoord.y));
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetPressure(pressure);
    item.SetTargetWindowId(-1);
    item.SetTwist(twist);

    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(item);
    pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);
    return true;
}

bool TabletToolTransformProcessor::OnTipMotion(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    CHKPF(tabletEvent);
    uint64_t time = libinput_event_tablet_tool_get_time_usec(tabletEvent);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent_->SetActionTime(time);
    if (IsTouching(tabletEvent)) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    } else {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_LEVITATE_MOVE);
    }
    int32_t targetDisplayId = pointerEvent_->GetTargetDisplayId();
    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        MMI_HILOGW("The pointer is expected, but not found");
        pointerEvent_->SetActionStartTime(time);
        pointerEvent_->SetTargetDisplayId(targetDisplayId);
        pointerEvent_->SetDeviceId(deviceId_);
        pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);

        item.SetPointerId(DEFAULT_POINTER_ID);
        item.SetDeviceId(deviceId_);
        item.SetDownTime(time);
    }

    double tiltX = libinput_event_tablet_tool_get_tilt_x(tabletEvent);
    double tiltY = libinput_event_tablet_tool_get_tilt_y(tabletEvent);
    double pressure = libinput_event_tablet_tool_get_pressure(tabletEvent);
    int32_t toolType = GetToolType(tabletEvent);
    int32_t twist = libinput_event_tablet_tool_get_twist(tabletEvent);

    item.SetToolType(toolType);

    PhysicalCoordinate tCoord;
    if (!CalculateCalibratedTipPoint(tabletEvent, targetDisplayId, tCoord, item)) {
        MMI_HILOGE("CalculateCalibratedTipPoint failed");
        return false;
    }

    item.SetDisplayXPos(tCoord.x);
    item.SetDisplayYPos(tCoord.y);
    item.SetRawDisplayX(static_cast<int32_t>(tCoord.x));
    item.SetRawDisplayY(static_cast<int32_t>(tCoord.y));
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetPressure(pressure);
    item.SetTwist(twist);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    return true;
}

bool TabletToolTransformProcessor::OnTipUp(struct libinput_event_tablet_tool* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    uint64_t time = libinput_event_tablet_tool_get_time_usec(event);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        MMI_HILOGE("GetPointerItem failed");
        return false;
    }
    item.SetPressed(false);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    return true;
}

bool TabletToolTransformProcessor::OnTipProximity(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    CHKPF(tabletEvent);
    uint64_t time = libinput_event_tablet_tool_get_time_usec(tabletEvent);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    bool tabletProximityState = libinput_event_tablet_tool_get_proximity_state(tabletEvent);
    if (tabletProximityState) {
        MMI_HILOGD("The pen is getting close and report proximity in event");
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    } else {
        MMI_HILOGD("The pen is getting away and report proximity out event");
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_PROXIMITY_OUT);
    }

    int32_t targetDisplayId = pointerEvent_->GetTargetDisplayId();
    double tiltX = libinput_event_tablet_tool_get_tilt_x(tabletEvent);
    double tiltY = libinput_event_tablet_tool_get_tilt_y(tabletEvent);
    double pressure = libinput_event_tablet_tool_get_pressure(tabletEvent);
    int32_t toolType = GetToolType(tabletEvent);

    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, item)) {
        MMI_HILOGW("The pointer is expected, but not found");
    }

    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetTargetDisplayId(targetDisplayId);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);

    item.SetPointerId(DEFAULT_POINTER_ID);
    item.SetDeviceId(deviceId_);
    item.SetDownTime(time);
    item.SetPressed(false);
    item.SetToolType(toolType);

    PhysicalCoordinate coord {};
    if (!CalculateCalibratedTipPoint(tabletEvent, targetDisplayId, coord, item)) {
        MMI_HILOGE("CalculateCalibratedTipPoint failed");
        return false;
    }

    item.SetDisplayXPos(coord.x);
    item.SetDisplayYPos(coord.y);
    item.SetRawDisplayX(static_cast<int32_t>(coord.x));
    item.SetRawDisplayY(static_cast<int32_t>(coord.y));
    item.SetTiltX(tiltX);
    item.SetTiltY(tiltY);
    item.SetPressure(pressure);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, item);
    return true;
}

bool TabletToolTransformProcessor::IsTouching(struct libinput_event_tablet_tool* tabletEvent)
{
    return tabletEvent != nullptr &&
        libinput_event_tablet_tool_get_tip_state(tabletEvent) == LIBINPUT_TABLET_TOOL_TIP_DOWN;
}

void TabletToolTransformProcessor::DrawTouchGraphic()
{
    if ((pointerEvent_ == nullptr) ||
        (pointerEvent_->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN)) {
        return;
    }
    CHKPV(current_);
    current_();
}

void TabletToolTransformProcessor::DrawTouchGraphicIdle()
{
    CHKPV(pointerEvent_);
    auto pointerAction = pointerEvent_->GetPointerAction();
    switch (pointerAction) {
        case PointerEvent::POINTER_ACTION_PROXIMITY_IN:
        case PointerEvent::POINTER_ACTION_DOWN:
        case PointerEvent::POINTER_ACTION_MOVE:
        case PointerEvent::POINTER_ACTION_LEVITATE_MOVE: {
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
            current_ = [this]() {
                DrawTouchGraphicDrawing();
            };
            break;
        }
        default: {
            return;
        }
    }
    WIN_MGR->DrawTouchGraphic(pointerEvent_);
    pointerEvent_->SetPointerAction(pointerAction);
}

void TabletToolTransformProcessor::DrawTouchGraphicDrawing()
{
    CHKPV(pointerEvent_);
    int32_t pointerId = pointerEvent_->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    bool isPointerItemExist = pointerEvent_->GetPointerItem(pointerId, pointerItem);
    bool originalPressedStatus = pointerItem.IsPressed();
    auto pointerAction = pointerEvent_->GetPointerAction();
    if (isPointerItemExist && !originalPressedStatus) {
        pointerItem.SetPressed(true);
        pointerEvent_->UpdatePointerItem(pointerId, pointerItem);
    }
    switch (pointerAction) {
        case PointerEvent::POINTER_ACTION_MOVE:
        case PointerEvent::POINTER_ACTION_PULL_MOVE:
        case PointerEvent::POINTER_ACTION_LEVITATE_MOVE:
        case PointerEvent::POINTER_ACTION_UP:
        case PointerEvent::POINTER_ACTION_PULL_UP: {
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
            break;
        }
        case PointerEvent::POINTER_ACTION_PROXIMITY_OUT: {
            auto pointerEvent = std::make_shared<PointerEvent>(*pointerEvent_);
            PointerEvent::PointerItem item {};
            if (pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
                pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
                WIN_MGR->DrawTouchGraphic(pointerEvent);
            }
            pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
            current_ = [this]() {
                DrawTouchGraphicIdle();
            };
            break;
        }
        default: {
            if (isPointerItemExist && !originalPressedStatus) {
                pointerItem.SetPressed(originalPressedStatus);
                pointerEvent_->UpdatePointerItem(pointerId, pointerItem);
            }
            return;
        }
    }
    WIN_MGR->DrawTouchGraphic(pointerEvent_);
    pointerEvent_->SetPointerAction(pointerAction);
    if (isPointerItemExist) {
        pointerItem.SetPressed(originalPressedStatus);
        pointerEvent_->UpdatePointerItem(pointerId, pointerItem);
    }
}

bool TabletToolTransformProcessor::OnToolButton(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto tabletEvent = libinput_event_get_tablet_tool_event(event);
    CHKPF(tabletEvent);
    auto button = libinput_event_tablet_tool_get_button(tabletEvent);
    if (button != BTN_STYLUS) {
        return false;
    }
    auto winMgr = WIN_MGR;
    if (winMgr == nullptr) {
        MMI_HILOGE("WinMgr is null");
        return false;
    }
    auto mouseInfo = winMgr->GetMouseInfo();
    auto time = GetSysClockTime();
    auto toolType = GetToolType(tabletEvent);

    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent_->SetTargetDisplayId(mouseInfo.displayId);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
    pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent_->SetButtonId(PointerEvent::MOUSE_BUTTON_RIGHT);

    auto btnState = libinput_event_tablet_tool_get_button_state(tabletEvent);
    if (btnState == LIBINPUT_BUTTON_STATE_PRESSED) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
        pointerEvent_->SetButtonPressed(PointerEvent::MOUSE_BUTTON_RIGHT);
    } else {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
        pointerEvent_->DeleteReleaseButton(PointerEvent::MOUSE_BUTTON_RIGHT);
    }

    PointerEvent::PointerItem mouseItem {};
    mouseItem.SetPointerId(DEFAULT_POINTER_ID);
    mouseItem.SetDeviceId(deviceId_);
    mouseItem.SetToolType(toolType);
    mouseItem.SetPressed(btnState == LIBINPUT_BUTTON_STATE_PRESSED);
    mouseItem.SetDownTime(time);
    mouseItem.SetDisplayXPos(mouseInfo.physicalX);
    mouseItem.SetDisplayYPos(mouseInfo.physicalY);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, mouseItem);

    MMI_HILOGI("Tablet tool button(%{public}d) %{public}s", button, (mouseItem.IsPressed()? "pressed" : "released"));
    return true;
}

bool TabletToolTransformProcessor::IsTabletPointer() const
{
    return INPUT_DEV_MGR->CheckDevice(deviceId_,
        [](const IInputDeviceManager::IInputDevice &dev) {
            return dev.IsMouse();
        });
}

bool TabletToolTransformProcessor::InitializeCalibration(struct libinput_device* device, int32_t displayId)
{
    CALL_DEBUG_ENTER;
    CHKPF(device);
    auto displayInfo = WIN_MGR->GetPhysicalDisplay(displayId);
    if (displayInfo == nullptr) {
        MMI_HILOGE("Failed to get display info for displayId:%{public}d", displayId);
        return false;
    }
    TabletCalibration calib {};
    InitializeDefaultCalibration(device, *displayInfo, calib);

    if (TabletToolTransformProcessor::IsCalibrationEnabled()) {
        CalculateCalibration(*displayInfo, calib);
    }

    MMI_HILOGI("Calibration saved for displayId:%{public}d, ScreenInfo:%{public}dx%{public}d, direction:%{public}d",
        calib.displayId, calib.screenWidth, calib.screenHeight, static_cast<int32_t>(calib.screenDirection));
    calibration_ = calib;
    return true;
}

void TabletToolTransformProcessor::InitializeDefaultCalibration(
    struct libinput_device* device, const OLD::DisplayInfo& displayInfo, TabletCalibration &calib)
{
    if (device == nullptr) {
        return;
    }
    calib.tabletMinX = libinput_device_get_axis_min(device, ABS_X);
    calib.tabletMaxX = libinput_device_get_axis_max(device, ABS_X);
    calib.tabletMinY = libinput_device_get_axis_min(device, ABS_Y);
    calib.tabletMaxY = libinput_device_get_axis_max(device, ABS_Y);
    MMI_HILOGI("Tablet original area: X[%{public}.0f, %{public}.0f], Y[%{public}.0f, %{public}.0f]",
        calib.tabletMinX, calib.tabletMaxX, calib.tabletMinY, calib.tabletMaxY);
    calib.calibratedMinX = calib.tabletMinX;
    calib.calibratedMaxX = calib.tabletMaxX;
    calib.calibratedMinY = calib.tabletMinY;
    calib.calibratedMaxY = calib.tabletMaxY;
    calib.displayId = displayInfo.id;
    calib.screenWidth = displayInfo.validWidth;
    calib.screenHeight = displayInfo.validHeight;
    calib.screenDirection = displayInfo.direction;
}

void TabletToolTransformProcessor::CalculateCalibration(const OLD::DisplayInfo& displayInfo, TabletCalibration &calib)
{
    double tabletWidth = calib.tabletMaxX - calib.tabletMinX;
    double tabletHeight = calib.tabletMaxY - calib.tabletMinY;
    double screenWidth = displayInfo.validWidth;
    double screenHeight = displayInfo.validHeight;

    if ((tabletWidth < DEFAULT_PRECISION) ||
        (tabletHeight < DEFAULT_PRECISION) ||
        (screenWidth < DEFAULT_PRECISION) ||
        (screenHeight < DEFAULT_PRECISION)) {
        MMI_HILOGE("Tablet or screen size is zero");
        return;
    }

    if (((tabletWidth > tabletHeight) && (screenWidth < screenHeight)) ||
        ((tabletWidth < tabletHeight) && (screenWidth > screenHeight))) {
        std::swap(screenWidth, screenHeight);
    }
    double tabletRatio = tabletWidth / tabletHeight;
    double screenRatio = screenWidth / screenHeight;

    MMI_HILOGI("Tablet ratio: %{public}.3f (%{public}.0fx%{public}.0f)", tabletRatio, tabletWidth, tabletHeight);
    MMI_HILOGI("Screen ratio: %{public}.3f (%{public}.0fx%{public}.0f, displayId:%{public}d)",
        screenRatio, screenWidth, screenHeight, displayInfo.id);

    if (tabletRatio > screenRatio) {
        double newHeight = tabletHeight;
        double newWidth = newHeight * screenRatio;

        calib.calibratedMinX = (tabletWidth - newWidth) / CONSTANT_TWO + calib.tabletMinX;
        calib.calibratedMaxX = calib.calibratedMinX + newWidth;
        calib.calibratedMinY = calib.tabletMinY;
        calib.calibratedMaxY = calib.tabletMaxY;
    } else {
        double newWidth = tabletWidth;
        double newHeight = newWidth / screenRatio;

        calib.calibratedMinX = calib.tabletMinX;
        calib.calibratedMaxX = calib.tabletMaxX;
        calib.calibratedMinY = (tabletHeight - newHeight) / CONSTANT_TWO + calib.tabletMinY;
        calib.calibratedMaxY = calib.calibratedMinY + newHeight;
    }

    MMI_HILOGI("Calibrated area: X[%{public}.0f, %{public}.0f], Y[%{public}.0f, %{public}.0f]",
        calib.calibratedMinX, calib.calibratedMaxX, calib.calibratedMinY, calib.calibratedMaxY);
}

bool TabletToolTransformProcessor::CalculateCalibratedTipPoint(struct libinput_event_tablet_tool* tabletEvent,
    int32_t& targetDisplayId, PhysicalCoordinate& coord, PointerEvent::PointerItem& pointerItem)
{
    CALL_DEBUG_ENTER;
    CHKPF(tabletEvent);
    if (IsTabletPointer()) {
        MMI_HILOGD("Associated tablet (INPUT_PROP_POINTER), use calibration path");
        return CalculateWithCalibration(tabletEvent, targetDisplayId, coord);
    }
    MMI_HILOGD("Independent tablet (INPUT_PROP_DIRECT), use original CalculateTipPoint");
    return WIN_MGR->CalculateTipPoint(tabletEvent, targetDisplayId, coord, pointerItem, deviceId_);
}

bool TabletToolTransformProcessor::IsScreenChanged(int32_t currentDisplayId) const
{
    if (!calibration_.has_value()) {
        return false;
    }

    if (calibration_->displayId != currentDisplayId) {
        MMI_HILOGI("Target display changed: %{public}d -> %{public}d",
            calibration_->displayId, currentDisplayId);
        return true;
    }

    auto displayInfo = WIN_MGR->GetPhysicalDisplay(currentDisplayId);
    if (displayInfo == nullptr) {
        MMI_HILOGW("Failed to get display info for displayId:%{public}d", currentDisplayId);
        return false;
    }

    if ((calibration_->screenWidth != displayInfo->validWidth) ||
        (calibration_->screenHeight != displayInfo->validHeight) ||
        (calibration_->screenDirection != displayInfo->direction)) {
        MMI_HILOGI("Screen (displayId:%{public}d) properties changed:"
            "[%{public}dx%{public}d, %{public}d] -> [%{public}dx%{public}d, %{public}d]",
            currentDisplayId,
            calibration_->screenWidth, calibration_->screenHeight,
            static_cast<int32_t>(calibration_->screenDirection),
            displayInfo->width, displayInfo->height,
            static_cast<int32_t>(displayInfo->direction));
        return true;
    }

    return false;
}

bool TabletToolTransformProcessor::CalculateScreenCoordinateWithCalibration(
    struct libinput_event_tablet_tool* tabletEvent,
    const OLD::DisplayInfo& displayInfo, PhysicalCoordinate& coord)
{
    CALL_DEBUG_ENTER;
    CHKPF(tabletEvent);
    if (!calibration_) {
        return false;
    }
    double tabletWidth = calibration_->tabletMaxX - calibration_->tabletMinX;
    double tabletHeight = calibration_->tabletMaxY - calibration_->tabletMinY;
    if ((tabletWidth < DEFAULT_PRECISION) || (tabletHeight < DEFAULT_PRECISION)) {
        return false;
    }
    double rawX = libinput_event_tablet_tool_get_x_transformed(tabletEvent, static_cast<uint32_t>(tabletWidth));
    double rawY = libinput_event_tablet_tool_get_y_transformed(tabletEvent, static_cast<uint32_t>(tabletHeight));
    MMI_HILOGD("Raw hardware coordinates: (%.1f, %.1f)", rawX, rawY);
    rawX = std::clamp(rawX, calibration_->calibratedMinX, calibration_->calibratedMaxX);
    rawY = std::clamp(rawY, calibration_->calibratedMinY, calibration_->calibratedMaxY);

    double calibratedWidth = calibration_->calibratedMaxX - calibration_->calibratedMinX;
    double calibratedHeight = calibration_->calibratedMaxY - calibration_->calibratedMinY;
    if ((calibratedWidth < DEFAULT_PRECISION) || (calibratedHeight < DEFAULT_PRECISION)) {
        return false;
    }
    double normalizedX = (rawX - calibration_->calibratedMinX) / calibratedWidth;
    double normalizedY = (rawY - calibration_->calibratedMinY) / calibratedHeight;
    double screenWidth = displayInfo.validWidth;
    double screenHeight = displayInfo.validHeight;

    if (((tabletWidth > tabletHeight) && (screenWidth < screenHeight)) ||
        ((tabletWidth < tabletHeight) && (screenWidth > screenHeight))) {
        coord.x = (1.0 - normalizedY) * screenWidth;
        coord.y = normalizedX * screenHeight;
    } else {
        coord.x = normalizedX * screenWidth;
        coord.y = normalizedY * screenHeight;
    }
    MMI_HILOGD("Calibrated screen coordinates: (%.1f, %.1f)", coord.x, coord.y);
    return true;
}

bool TabletToolTransformProcessor::CalculateWithCalibration(
    struct libinput_event_tablet_tool* tabletEvent, int32_t& targetDisplayId, PhysicalCoordinate& coord)
{
    CALL_DEBUG_ENTER;
    CHKPF(tabletEvent);
    int32_t displayIdForCalibration = targetDisplayId;

    if (displayIdForCalibration < 0) {
        displayIdForCalibration = WIN_MGR->GetMainDisplayId();
    }
    auto displayInfo = WIN_MGR->GetPhysicalDisplay(displayIdForCalibration);
    if (displayInfo == nullptr) {
        MMI_HILOGE("No display(%{public}d)", displayIdForCalibration);
        return false;
    }
    targetDisplayId = displayIdForCalibration;

    if (!calibration_ || IsScreenChanged(displayIdForCalibration)) {
        INPUT_DEV_MGR->ForDevice(deviceId_,
            [this, displayIdForCalibration](const IInputDeviceManager::IInputDevice &dev) {
                InitializeCalibration(dev.GetRawDevice(), displayIdForCalibration);
            });
    }
    if (!CalculateScreenCoordinateWithCalibration(tabletEvent, *displayInfo, coord)) {
        MMI_HILOGE("CalculateScreenCoordinateWithCalibration failed");
        return false;
    }
    return true;
}

bool TabletToolTransformProcessor::IsCalibrationEnabled()
{
    static bool calibrationEnabled { false };
    static std::once_flag flag;

    std::call_once(flag, []() {
        TabletToolTransformProcessor::LoadProductConfig(calibrationEnabled);
    });
    return calibrationEnabled;
}

void TabletToolTransformProcessor::LoadProductConfig(bool &enabled)
{
    enabled = false;
    LoadConfig(CONFIG_NAME,
        [&enabled](const char* cfgPath, cJSON* jsonCfg) {
            return ReadTabletCalibrationConfig(cfgPath, jsonCfg, enabled);
        });
}

bool TabletToolTransformProcessor::ReadTabletCalibrationConfig(const char* cfgPath, cJSON* jsonCfg, bool& enabled)
{
    if (!cJSON_IsObject(jsonCfg)) {
        MMI_HILOGE("Config is not json object");
        return false;
    }
    cJSON *jsonTabletCalibration = cJSON_GetObjectItemCaseSensitive(jsonCfg, "TabletCalibration");
    if (jsonTabletCalibration == nullptr) {
        MMI_HILOGE("Invalid config(%{private}s): no 'TabletCalibration'", cfgPath);
        return true;
    }
    if (!cJSON_IsObject(jsonTabletCalibration)) {
        MMI_HILOGE("TabletCalibration is not object");
        return false;
    }
    cJSON *jsonEnabled = cJSON_GetObjectItemCaseSensitive(jsonTabletCalibration, "enabled");
    if (jsonEnabled == nullptr) {
        MMI_HILOGE("Invalid config(%{private}s): no 'TabletCalibration.enabled'", cfgPath);
        return true;
    }
    if (!cJSON_IsBool(jsonEnabled)) {
        MMI_HILOGE("enabled is not boolean");
        return false;
    }
    enabled = cJSON_IsTrue(jsonEnabled);
    MMI_HILOGI("Tablet calibration config loaded from '%{private}s'", cfgPath);
    return true;
}
} // namespace MMI
} // namespace OHOS
