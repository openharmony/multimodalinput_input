/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "touchpad_transform_processor.h"

#include <linux/input.h>

#include <sstream>

#include "dfx_hisysevent.h"
#include "event_log_helper.h"
#include "i_input_windows_manager.h"
#include "i_preference_manager.h"
#include "mmi_log.h"
#include "mouse_device_state.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchPadTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MT_TOOL_NONE { -1 };
constexpr int32_t BTN_DOWN { 1 };
constexpr int32_t FINGER_COUNT_MAX { 5 };
constexpr int32_t FINGER_TAP_MIN { 3 };
constexpr int32_t FINGER_TAP_THREE { 3 };
constexpr int32_t TP_SYSTEM_PINCH_FINGER_CNT { 2 };
constexpr int32_t DEFAULT_POINTER_ID { 0 };
constexpr int32_t MIN_ROWS { 1 };
constexpr int32_t MAX_ROWS { 100 };
constexpr int32_t DEFAULT_ROWS { 3 };

const std::string TOUCHPAD_FILE_NAME = "touchpad_settings.xml";
std::string THREE_FINGER_TAP_KEY = "touchpadThreeFingerTap";
} // namespace

TouchPadTransformProcessor::TouchPadTransformProcessor(int32_t deviceId)
    : deviceId_(deviceId)
{
    InitToolType();
}

int32_t TouchPadTransformProcessor::OnEventTouchPadDown(struct libinput_event *event)
{
    CALL_INFO_TRACE;
    CHKPR(event, RET_ERR);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPR(touchpad, RET_ERR);
    auto device = libinput_event_get_device(event);
    CHKPR(device, RET_ERR);

    uint64_t time = libinput_event_touchpad_get_time_usec(touchpad);
    auto pointIds = pointerEvent_->GetPointerIds();
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem item;
    int32_t longAxis = libinput_event_touchpad_get_touch_contact_long_axis(touchpad);
    int32_t shortAxis = libinput_event_touchpad_get_touch_contact_short_axis(touchpad);
    double pressure = libinput_event_touchpad_get_pressure(touchpad);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);
    double logicalX = libinput_event_touchpad_get_x(touchpad);
    double logicalY = libinput_event_touchpad_get_y(touchpad);
    double toolPhysicalX = libinput_event_touchpad_get_tool_x(touchpad);
    double toolPhysicalY = libinput_event_touchpad_get_tool_y(touchpad);
    double toolWidth = libinput_event_touchpad_get_tool_width(touchpad);
    double toolHeight = libinput_event_touchpad_get_tool_height(touchpad);
    int32_t toolType = GetTouchPadToolType(touchpad, device);
    if (toolType == PointerEvent::TOOL_TYPE_PALM) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    }
    MMI_HILOGD("The pointer action is %{public}d", pointerEvent_->GetPointerAction());
    item.SetLongAxis(longAxis);
    item.SetShortAxis(shortAxis);
    item.SetPressure(pressure);
    item.SetToolType(toolType);
    item.SetPointerId(seatSlot);
    item.SetDownTime(time);
    item.SetPressed(true);
    item.SetDisplayX(static_cast<int32_t>(logicalX));
    item.SetDisplayY(static_cast<int32_t>(logicalY));
    item.SetToolDisplayX(static_cast<int32_t>(toolPhysicalX));
    item.SetToolDisplayY(static_cast<int32_t>(toolPhysicalY));
    item.SetToolWidth(static_cast<int32_t>(toolWidth));
    item.SetToolHeight(static_cast<int32_t>(toolHeight));
    item.SetDeviceId(deviceId_);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(item);
    pointerEvent_->SetPointerId(seatSlot);

    return RET_OK;
}

int32_t TouchPadTransformProcessor::OnEventTouchPadMotion(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, RET_ERR);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPR(touchpad, RET_ERR);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);
    auto device = libinput_event_get_device(event);
    CHKPR(device, RET_ERR);

    uint64_t time = libinput_event_touchpad_get_time_usec(touchpad);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(seatSlot, item)) {
        MMI_HILOGD("Can't find the pointer item data, seatSlot:%{public}d, errCode:%{public}d",
                   seatSlot, PARAM_INPUT_FAIL);
        return RET_ERR;
    }
    int32_t longAxis = libinput_event_touchpad_get_touch_contact_long_axis(touchpad);
    int32_t shortAxis = libinput_event_touchpad_get_touch_contact_short_axis(touchpad);
    double pressure = libinput_event_touchpad_get_pressure(touchpad);
    double logicalX = libinput_event_touchpad_get_x(touchpad);
    double logicalY = libinput_event_touchpad_get_y(touchpad);
    double toolPhysicalX = libinput_event_touchpad_get_tool_x(touchpad);
    double toolPhysicalY = libinput_event_touchpad_get_tool_y(touchpad);
    double toolWidth = libinput_event_touchpad_get_tool_width(touchpad);
    double toolHeight = libinput_event_touchpad_get_tool_height(touchpad);
    int32_t toolType = GetTouchPadToolType(touchpad, device);
    if (toolType == PointerEvent::TOOL_TYPE_PALM) {
        MMI_HILOGD("Tool type is palm");
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    }
    MMI_HILOGD("The pointer action is %{public}d", pointerEvent_->GetPointerAction());

    item.SetLongAxis(longAxis);
    item.SetShortAxis(shortAxis);
    item.SetPressure(pressure);
    item.SetDisplayX(static_cast<int32_t>(logicalX));
    item.SetDisplayY(static_cast<int32_t>(logicalY));
    item.SetToolDisplayX(static_cast<int32_t>(toolPhysicalX));
    item.SetToolDisplayY(static_cast<int32_t>(toolPhysicalY));
    item.SetToolWidth(static_cast<int32_t>(toolWidth));
    item.SetToolHeight(static_cast<int32_t>(toolHeight));
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);

    return RET_OK;
}

int32_t TouchPadTransformProcessor::OnEventTouchPadUp(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, RET_ERR);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPR(touchpad, RET_ERR);
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);

    uint64_t time = libinput_event_touchpad_get_time_usec(touchpad);
    pointerEvent_->SetActionTime(time);
    if (MULTI_FINGERTAP_HDR->GetMultiFingersState() == MulFingersTap::TRIPLETAP) {
        SetTouchPadMultiTapData();
    } else {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    }
    PointerEvent::PointerItem item;
    if (!pointerEvent_->GetPointerItem(seatSlot, item)) {
        MMI_HILOGE("Can't find the pointer item data, seatSlot:%{public}d, errCode:%{public}d",
                   seatSlot, PARAM_INPUT_FAIL);
        return RET_ERR;
    }
    item.SetPressed(false);
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);

    return RET_OK;
}

std::shared_ptr<PointerEvent> TouchPadTransformProcessor::OnEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPP(event);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
        CHKPP(pointerEvent_);
    }

    int32_t ret = RET_OK;
    int32_t type = libinput_event_get_type(event);
    switch (type) {
        case LIBINPUT_EVENT_TOUCHPAD_DOWN: {
            ret = OnEventTouchPadDown(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_UP: {
            ret = OnEventTouchPadUp(event);
            break;
        }
        case LIBINPUT_EVENT_TOUCHPAD_MOTION: {
            ret = OnEventTouchPadMotion(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN: {
            ret = OnEventTouchPadSwipeBegin(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE: {
            ret = OnEventTouchPadSwipeUpdate(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_END: {
            ret = OnEventTouchPadSwipeEnd(event);
            break;
        }

        case LIBINPUT_EVENT_GESTURE_PINCH_BEGIN: {
            ret = OnEventTouchPadPinchBegin(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_UPDATE: {
            ret = OnEventTouchPadPinchUpdate(event);
            break;
        }
        case LIBINPUT_EVENT_GESTURE_PINCH_END: {
            ret = OnEventTouchPadPinchEnd(event);
            break;
        }
        default: {
            MMI_HILOGW("Touch pad action is not found");
            return nullptr;
        }
    }

    if (ret != RET_OK) {
        MMI_HILOGW("The event on touch pad execute fail");
        return nullptr;
    }

    pointerEvent_->UpdateId();
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    MMI_HILOGD("Pointer event dispatcher of server:");
    EventLogHelper::PrintEventData(pointerEvent_, pointerEvent_->GetPointerAction(),
        pointerEvent_->GetPointerIds().size(), MMI_LOG_FREEZE);
    auto device = INPUT_DEV_MGR->GetInputDevice(pointerEvent_->GetDeviceId());
    CHKPP(device);
    if (pointerEvent_->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE &&
        pointerEvent_->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE) {
        aggregator_.Record(MMI_LOG_FREEZE, device->GetName() + ", TW: " +
            std::to_string(pointerEvent_->GetTargetWindowId()) + ", action: " + pointerEvent_->DumpPointerAction(),
            std::to_string(pointerEvent_->GetId()));
    }

    return pointerEvent_;
}

int32_t TouchPadTransformProcessor::GetTouchPadToolType(
    struct libinput_event_touch *touchpad, struct libinput_device *device)
{
    int32_t toolType = libinput_event_touchpad_get_tool_type(touchpad);
    switch (toolType) {
        case MT_TOOL_NONE: {
            return GetTouchPadToolType(device);
        }
        case MT_TOOL_FINGER: {
            return PointerEvent::TOOL_TYPE_FINGER;
        }
        case MT_TOOL_PEN: {
            return PointerEvent::TOOL_TYPE_PEN;
        }
        case MT_TOOL_PALM: {
            MMI_HILOGD("toolType is MT_TOOL_PALM");
            return PointerEvent::TOOL_TYPE_PALM;
        }
        default : {
            MMI_HILOGW("Unknown tool type, identified as finger, toolType:%{public}d", toolType);
            return PointerEvent::TOOL_TYPE_FINGER;
        }
    }
}

int32_t TouchPadTransformProcessor::GetTouchPadToolType(struct libinput_device *device)
{
    for (const auto &item : vecToolType_) {
        if (libinput_device_touchpad_btn_tool_type_down(device, item.first) == BTN_DOWN) {
            MMI_HILOGD("The btn tool type is %{public}d", item.second);
            return item.second;
        }
    }
    MMI_HILOGD("Unknown Btn tool type, identified as finger");
    return PointerEvent::TOOL_TYPE_FINGER;
}

int32_t TouchPadTransformProcessor::SetTouchPadSwipeData(struct libinput_event *event, int32_t action)
{
    CALL_DEBUG_ENTER;

    bool tpSwipeSwitch = true;
    GetTouchpadSwipeSwitch(tpSwipeSwitch);

    if (!tpSwipeSwitch) {
        MMI_HILOGD("Touchpad swipe switch is false");
        return RET_ERR;
    }

    CHKPR(event, RET_ERR);
    struct libinput_event_gesture *gesture = libinput_event_get_gesture_event(event);
    CHKPR(gesture, RET_ERR);

    int64_t time = static_cast<int64_t>(libinput_event_gesture_get_time(gesture));
    pointerEvent_->SetActionTime(GetSysClockTime());
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetPointerAction(action);
    pointerEvent_->SetDeviceId(deviceId_);

    int32_t fingerCount = libinput_event_gesture_get_finger_count(gesture);
    if (fingerCount < 0 || fingerCount > FINGER_COUNT_MAX) {
        MMI_HILOGE("Finger count is invalid");
        return RET_ERR;
    }
    if (fingerCount == FINGER_TAP_THREE) {
        GetTouchpadThreeFingersTapSwitch(tpSwipeSwitch);
        if (!tpSwipeSwitch) {
            return RET_OK;
        }
    }
    pointerEvent_->SetFingerCount(fingerCount);

    if (fingerCount == 0) {
        MMI_HILOGD("There is no finger in swipe action:%{public}d", action);
        return RET_ERR;
    }

    AddItemForEventWhileSetSwipeData(time, gesture, fingerCount);
    
    if (action == PointerEvent::POINTER_ACTION_SWIPE_BEGIN) {
        MMI_HILOGE("Start report for POINTER_ACTION_SWIPE_BEGIN");
        DfxHisysevent::StatisticTouchpadGesture(pointerEvent_);
    }

    return RET_OK;
}

int32_t TouchPadTransformProcessor::AddItemForEventWhileSetSwipeData(int64_t time, libinput_event_gesture *gesture,
                                                                     int32_t fingerCount)
{
    int32_t sumX = 0;
    int32_t sumY = 0;
    if (fingerCount == 0) {
        MMI_HILOGD("There is no finger in swipe action");
        return RET_ERR;
    }
    for (int32_t i = 0; i < fingerCount; i++) {
        sumX += libinput_event_gesture_get_device_coords_x(gesture, i);
        sumY += libinput_event_gesture_get_device_coords_y(gesture, i);
    }
    PointerEvent::PointerItem pointerItem;
    pointerEvent_->GetPointerItem(DEFAULT_POINTER_ID, pointerItem);
    pointerItem.SetPressed(MouseState->IsLeftBtnPressed());
    pointerItem.SetDownTime(time);
    pointerItem.SetDisplayX(sumX / fingerCount);
    pointerItem.SetDisplayY(sumY / fingerCount);
    pointerItem.SetDeviceId(deviceId_);
    pointerItem.SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, pointerItem);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    return RET_OK;
}

int32_t TouchPadTransformProcessor::OnEventTouchPadSwipeBegin(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadSwipeData(event, PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
}

int32_t TouchPadTransformProcessor::OnEventTouchPadSwipeUpdate(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadSwipeData(event, PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
}

int32_t TouchPadTransformProcessor::OnEventTouchPadSwipeEnd(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadSwipeData(event, PointerEvent::POINTER_ACTION_SWIPE_END);
}

void TouchPadTransformProcessor::SetTouchPadMultiTapData()
{
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_TRIPTAP);
    auto state = MULTI_FINGERTAP_HDR->GetMultiFingersState();
    pointerEvent_->SetFingerCount(static_cast<int32_t>(state));
}

int32_t TouchPadTransformProcessor::SetTouchPadPinchData(struct libinput_event *event, int32_t action)
{
    CALL_DEBUG_ENTER;

    bool tpPinchSwitch = true;
    GetTouchpadPinchSwitch(tpPinchSwitch);

    CHKPR(event, RET_ERR);
    auto gesture = libinput_event_get_gesture_event(event);
    CHKPR(gesture, RET_ERR);
    int32_t fingerCount = libinput_event_gesture_get_finger_count(gesture);
    if (fingerCount <= 0 || fingerCount > FINGER_COUNT_MAX) {
        MMI_HILOGE("Finger count is invalid");
        return RET_ERR;
    }

    if (!tpPinchSwitch && fingerCount == TP_SYSTEM_PINCH_FINGER_CNT) {
        MMI_HILOGD("Touchpad pinch switch is false");
        return RET_ERR;
    }

    int64_t time = static_cast<int64_t>(libinput_event_gesture_get_time(gesture));
    double scale = libinput_event_gesture_get_scale(gesture);

    pointerEvent_->SetActionTime(GetSysClockTime());
    pointerEvent_->SetActionStartTime(time);

    SetPinchPointerItem(time);

    ProcessTouchPadPinchDataEvent(fingerCount, action, scale);

    return RET_OK;
}

void TouchPadTransformProcessor::SetPinchPointerItem(int64_t time)
{
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetDownTime(time);
    pointerItem.SetPressed(MouseState->IsLeftBtnPressed());
    pointerItem.SetPointerId(DEFAULT_POINTER_ID);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    auto mouseInfo = WIN_MGR->GetMouseInfo();
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
    pointerEvent_->UpdatePointerItem(DEFAULT_POINTER_ID, pointerItem);
}

void TouchPadTransformProcessor::ProcessTouchPadPinchDataEvent(int32_t fingerCount, int32_t action, double scale)
{
    pointerEvent_->ClearButtonPressed();
    std::vector<int32_t> pressedButtons;
    MouseState->GetPressedButtons(pressedButtons);
    for (const auto &item : pressedButtons) {
        pointerEvent_->SetButtonPressed(item);
    }

    pointerEvent_->SetFingerCount(fingerCount);
    pointerEvent_->SetDeviceId(deviceId_);
    auto mouseInfo = WIN_MGR->GetMouseInfo();
    pointerEvent_->SetTargetDisplayId(mouseInfo.displayId);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetPointerId(DEFAULT_POINTER_ID);
    pointerEvent_->SetPointerAction(action);
    pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);

    if (fingerCount == TP_SYSTEM_PINCH_FINGER_CNT) {
        pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
    } else {
        pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
        pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, scale);
    }

    if (pointerEvent_->GetFingerCount() == TP_SYSTEM_PINCH_FINGER_CNT) {
        MMI_HILOGD("The finger count achieves two");
        WIN_MGR->UpdateTargetPointer(pointerEvent_);
    }

    // only three or four finger pinch need to statistic
    if (action == PointerEvent::POINTER_ACTION_AXIS_BEGIN && fingerCount > TP_SYSTEM_PINCH_FINGER_CNT) {
        DfxHisysevent::StatisticTouchpadGesture(pointerEvent_);
    }
}

int32_t TouchPadTransformProcessor::OnEventTouchPadPinchBegin(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadPinchData(event, PointerEvent::POINTER_ACTION_AXIS_BEGIN);
}

int32_t TouchPadTransformProcessor::OnEventTouchPadPinchUpdate(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadPinchData(event, PointerEvent::POINTER_ACTION_AXIS_UPDATE);
}

int32_t TouchPadTransformProcessor::OnEventTouchPadPinchEnd(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    return SetTouchPadPinchData(event, PointerEvent::POINTER_ACTION_AXIS_END);
}

void TouchPadTransformProcessor::InitToolType()
{
    vecToolType_.push_back(std::make_pair(BTN_TOOL_PEN, PointerEvent::TOOL_TYPE_PEN));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_RUBBER, PointerEvent::TOOL_TYPE_RUBBER));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_BRUSH, PointerEvent::TOOL_TYPE_BRUSH));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_PENCIL, PointerEvent::TOOL_TYPE_PENCIL));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_AIRBRUSH, PointerEvent::TOOL_TYPE_AIRBRUSH));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_FINGER, PointerEvent::TOOL_TYPE_FINGER));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_MOUSE, PointerEvent::TOOL_TYPE_MOUSE));
    vecToolType_.push_back(std::make_pair(BTN_TOOL_LENS, PointerEvent::TOOL_TYPE_LENS));
}

int32_t TouchPadTransformProcessor::SetTouchpadSwipeSwitch(bool switchFlag)
{
    std::string name = "touchpadSwipe";
    if (PutConfigDataToDatabase(name, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set touchpad swpie switch flag to mem");
        return RET_ERR;
    }

    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_SWIPE_SETTING,
        switchFlag);
    return RET_OK;
}

void TouchPadTransformProcessor::GetTouchpadSwipeSwitch(bool &switchFlag)
{
    std::string name = "touchpadSwipe";
    GetConfigDataFromDatabase(name, switchFlag);
}

int32_t TouchPadTransformProcessor::SetTouchpadPinchSwitch(bool switchFlag)
{
    std::string name = "touchpadPinch";
    if (PutConfigDataToDatabase(name, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set touchpad pinch switch flag to mem");
        return RET_ERR;
    }

    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_PINCH_SETTING,
        switchFlag);
    return RET_OK;
}

void TouchPadTransformProcessor::GetTouchpadPinchSwitch(bool &switchFlag)
{
    std::string name = "touchpadPinch";
    GetConfigDataFromDatabase(name, switchFlag);
}

int32_t TouchPadTransformProcessor::SetTouchpadRotateSwitch(bool rotateSwitch)
{
    std::string name = "touchpadRotate";
    if (PutConfigDataToDatabase(name, rotateSwitch) != RET_OK) {
        MMI_HILOGE("PutConfigDataToDatabase failed");
        return RET_ERR;
    }

    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_ROTATE_SETTING,
        rotateSwitch);
    return RET_OK;
}

void TouchPadTransformProcessor::GetTouchpadRotateSwitch(bool &rotateSwitch)
{
    std::string name = "touchpadRotate";
    GetConfigDataFromDatabase(name, rotateSwitch);
}

int32_t TouchPadTransformProcessor::SetTouchpadScrollRows(int32_t rows)
{
    CALL_DEBUG_ENTER;
    int32_t newRows = std::clamp(rows, MIN_ROWS, MAX_ROWS);
    std::string name = "touchpadScrollRows";
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, TOUCHPAD_FILE_NAME, newRows);
    MMI_HILOGD("Set touchpad scroll rows successfully, rows:%{public}d", newRows);
    return ret;
}

int32_t TouchPadTransformProcessor::GetTouchpadScrollRows()
{
    CALL_DEBUG_ENTER;
    std::string name = "touchpadScrollRows";
    int32_t rows = PREFERENCES_MGR->GetIntValue(name, DEFAULT_ROWS);
    MMI_HILOGD("Get touchpad scroll rows successfully, rows:%{public}d", rows);
    return rows;
}

int32_t TouchPadTransformProcessor::PutConfigDataToDatabase(std::string &key, bool value)
{
    return PREFERENCES_MGR->SetBoolValue(key, TOUCHPAD_FILE_NAME, value);
}

void TouchPadTransformProcessor::GetConfigDataFromDatabase(std::string &key, bool &value)
{
    value = PREFERENCES_MGR->GetBoolValue(key, true);
}

std::shared_ptr<PointerEvent> TouchPadTransformProcessor::GetPointerEvent()
{
    return pointerEvent_;
}

MultiFingersTapHandler::MultiFingersTapHandler() {}

MultiFingersTapHandler::~MultiFingersTapHandler() {}

int32_t MultiFingersTapHandler::HandleMulFingersTap(struct libinput_event_touch *event, int32_t type)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, RET_ERR);
    // if is not multifigners tap, return.
    if (tapTrends_ == TapTrends::NOMULTAP) {
        MMI_HILOGD("The tapsTrends is MOMULTAP");
        return RET_OK;
    }
    // calculator delta time, if is larger than threshold, return.
    auto time = libinput_event_touchpad_get_time_usec(event);
    uint64_t deltaTime = 0;
    if (tapTrends_ != TapTrends::BEGIN) {
        deltaTime = time - lastTime;
    } else {
        beginTime = time;
    }
    lastTime = time;
    if ((deltaTime > perTimeThreshold) || ((lastTime - beginTime) > totalTimeThreshold)) {
        MMI_HILOGD("Not multitap, single time interval or total time interval is out of range."
            "single:%{public}" PRId64 ", total:%{public}" PRId64, deltaTime, (lastTime - beginTime));
        SetMULTI_FINGERTAP_HDRDefault();
        return RET_OK;
    }
    if (type == LIBINPUT_EVENT_TOUCHPAD_DOWN) {
        // if trends is up, is not multifigners tap, return.
        if ((tapTrends_ == TapTrends::UPING) || !CanAddToPointerMaps(event)) {
            MMI_HILOGD("The trends is up, is not a multifigners tap event");
            SetMULTI_FINGERTAP_HDRDefault();
            return RET_OK;
        } else {
            downCnt++;
            tapTrends_ = TapTrends::DOWNING;
        }
    } else if ((type == LIBINPUT_EVENT_TOUCHPAD_UP) && !CanUnsetPointerItem(event)) {
        upCnt++;
        tapTrends_ = TapTrends::UPING;
    }

    if ((upCnt == downCnt) && (upCnt >= FINGER_TAP_MIN) && (upCnt <= FINGER_COUNT_MAX)) {
        multiFingersState_ = static_cast<MulFingersTap>(upCnt);
        MMI_HILOGD("This is multifinger tap event, finger count:%{public}d", upCnt);
    }
    return RET_OK;
}

void MultiFingersTapHandler::SetMULTI_FINGERTAP_HDRDefault(bool isAlldefault)
{
    downCnt = 0;
    upCnt = 0;
    tapTrends_ = TapTrends::BEGIN;
    beginTime = 0;
    lastTime = 0;
    if (isAlldefault) {
        MMI_HILOGD("Reset the multi finger state is NO_TAP");
        multiFingersState_ = MulFingersTap::NO_TAP;
    }
    pointerMaps.clear();
}

bool MultiFingersTapHandler::ClearPointerItems(std::shared_ptr<PointerEvent> pointer)
{
    auto ids_ = pointer->GetPointerIds();
    for (const auto &id : ids_) {
        pointer->RemovePointerItem(id);
    }
    return true;
}

MulFingersTap MultiFingersTapHandler::GetMultiFingersState() const
{
    return multiFingersState_;
}

bool MultiFingersTapHandler::CanAddToPointerMaps(struct libinput_event_touch *event)
{
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(event);
    if (pointerMaps.find(seatSlot) != pointerMaps.end()) {
        MMI_HILOGD("The pointerMaps can not find the seatSlot");
        return false;
    }
    auto currentX = libinput_event_touchpad_get_x(event);
    auto currentY = libinput_event_touchpad_get_y(event);
    pointerMaps[seatSlot] = {currentX, currentY};
    return true;
}

bool MultiFingersTapHandler::CanUnsetPointerItem(struct libinput_event_touch *event)
{
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(event);
    if (pointerMaps.find(seatSlot) != pointerMaps.end()) {
        MMI_HILOGD("The pointerMaps can not find the seatSlot");
        return false;
    } else {
        pointerMaps[seatSlot] = {-1.0F, -1.0F};
        return true;
    }
}

int32_t TouchPadTransformProcessor::SetTouchpadThreeFingersTapSwitch(bool switchFlag)
{
    if (PutConfigDataToDatabase(THREE_FINGER_TAP_KEY, switchFlag) != RET_OK) {
        MMI_HILOGE("Failed to set touchpad three fingers switch flag to mem.");
        return RET_ERR;
    }
    DfxHisysevent::ReportTouchpadSettingState(DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_PINCH_SETTING,
        switchFlag);
    return RET_OK;
}

int32_t TouchPadTransformProcessor::GetTouchpadThreeFingersTapSwitch(bool &switchFlag)
{
    GetConfigDataFromDatabase(THREE_FINGER_TAP_KEY, switchFlag);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
