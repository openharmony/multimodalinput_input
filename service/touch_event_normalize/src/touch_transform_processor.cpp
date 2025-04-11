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

#include "touch_transform_processor.h"

#include <linux/input.h>

#include "bytrace_adapter.h"
#include "event_log_helper.h"
#include "input_device_manager.h"
#include "fingersense_wrapper.h"
#include "input_event_handler.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MT_TOOL_NONE { -1 };
constexpr int32_t BTN_DOWN { 1 };
constexpr int32_t DRIVER_NUMBER { 8 };
constexpr uint32_t TOUCH_CANCEL_MASK { 1U << 29U };
constexpr int32_t PRINT_INTERVAL_COUNT { 50 };
} // namespace

TouchTransformProcessor::TouchTransformProcessor(int32_t deviceId)
    : deviceId_(deviceId)
{
    InitToolTypes();
}

bool TouchTransformProcessor::OnEventTouchCancel(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto touch = libinput_event_get_touch_event(event);
    CHKPF(touch);
    MMI_HILOGI("process Touch Cancel event");
    uint64_t time = libinput_event_touch_get_time_usec(touch);
    CHKPF(pointerEvent_);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);

    EventTouch touchInfo;
    int32_t logicalDisplayId = pointerEvent_->GetTargetDisplayId();
    if (!WIN_MGR->TouchPointToDisplayPoint(deviceId_, touch, touchInfo, logicalDisplayId)) {
        MMI_HILOGE("Get TouchMotionPointToDisplayPoint failed");
        return false;
    }
    PointerEvent::PointerItem item;
    int32_t seatSlot = libinput_event_touch_get_seat_slot(touch);
    if (!(pointerEvent_->GetPointerItem(seatSlot, item))) {
        MMI_HILOGE("Get pointer parameter failed");
        return false;
    }
    int32_t blobId = libinput_event_touch_get_blob_id(touch);
    item.SetBlobId(blobId);
    double pressure = libinput_event_touch_get_pressure(touch);
    int32_t moveFlag = libinput_event_touch_get_move_flag(touch);
    int32_t longAxis = libinput_event_get_touch_contact_long_axis(touch);
    if (static_cast<uint32_t>(longAxis) & TOUCH_CANCEL_MASK) {
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
        DfxHisysevent::ReportPointerEventExitTimes(PointerEventStatistics::STYLUS_INTERRUPT_TOUCH);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
        pointerItemCancelMarks_.emplace(seatSlot, true);
    }
    int32_t shortAxis = libinput_event_get_touch_contact_short_axis(touch);
    item.SetMoveFlag(moveFlag);
    item.SetPressure(pressure);
    item.SetLongAxis(longAxis);
    item.SetShortAxis(shortAxis);
    item.SetDisplayX(touchInfo.point.x);
    item.SetDisplayY(touchInfo.point.y);
    item.SetDisplayXPos(touchInfo.point.x);
    item.SetDisplayYPos(touchInfo.point.y);
    item.SetRawDisplayX(touchInfo.point.x);
    item.SetRawDisplayY(touchInfo.point.y);
    item.SetToolDisplayX(touchInfo.toolRect.point.x);
    item.SetToolDisplayY(touchInfo.toolRect.point.y);
    item.SetToolWidth(touchInfo.toolRect.width);
    item.SetToolHeight(touchInfo.toolRect.height);
    pointerEvent_->SetTargetWindowId(item.GetTargetWindowId());
    auto windowInfo = WIN_MGR->GetWindowAndDisplayInfo(item.GetTargetWindowId(), pointerEvent_->GetTargetDisplayId());
    pointerEvent_->SetAgentWindowId(windowInfo->agentWindowId);
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);
    pointerEvent_->ClearFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    return true;
}

bool TouchTransformProcessor::OnEventTouchDown(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto touch = libinput_event_get_touch_event(event);
    CHKPF(touch);
    auto device = libinput_event_get_device(event);
    CHKPF(device);
    EventTouch touchInfo;
    int32_t logicalDisplayId = -1;
    if (!WIN_MGR->TouchPointToDisplayPoint(deviceId_, touch, touchInfo, logicalDisplayId)) {
        MMI_HILOGE("TouchDownPointToDisplayPoint failed");
        return false;
    }
    auto pointIds = pointerEvent_->GetPointerIds();
    uint64_t time = libinput_event_touch_get_time_usec(touch);
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
        pointerEvent_->SetTargetDisplayId(logicalDisplayId);
    }
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem item;
    int32_t blobId = libinput_event_touch_get_blob_id(touch);
    item.SetBlobId(blobId);
    double pressure = libinput_event_touch_get_pressure(touch);
    int32_t seatSlot = libinput_event_touch_get_seat_slot(touch);
    // we clean up pointerItem's cancel mark at down stage to ensure newer event
    // always starts with a clean and inital state
    if (pointerItemCancelMarks_.find(seatSlot) != pointerItemCancelMarks_.end()) {
        pointerItemCancelMarks_.erase(seatSlot);
    }
    int32_t moveFlag = libinput_event_touch_get_move_flag(touch);
    int32_t longAxis = libinput_event_get_touch_contact_long_axis(touch);
    int32_t shortAxis = libinput_event_get_touch_contact_short_axis(touch);
    item.SetMoveFlag(moveFlag);
    item.SetPressure(pressure);
    item.SetLongAxis(longAxis);
    item.SetShortAxis(shortAxis);
    item.SetPointerId(seatSlot);
    item.SetDownTime(time);
    item.SetPressed(true);
    UpdatePointerItemProperties(item, touchInfo);
    item.SetDeviceId(deviceId_);
    int32_t toolType = GetTouchToolType(touch, device);
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    auto keyHandler = InputHandler->GetKeyCommandHandler();
    if (keyHandler != nullptr && (!keyHandler->SkipKnuckleDetect())) {
        NotifyFingersenseProcess(item, toolType);
    } else {
        MMI_HILOGD("Skip fingersense detect");
    }
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    item.SetToolType(toolType);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->AddPointerItem(item);
    pointerEvent_->SetPointerId(seatSlot);
    pointerEvent_->ClearFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    return true;
}

void TouchTransformProcessor::UpdatePointerItemProperties(PointerEvent::PointerItem &item, EventTouch &touchInfo)
{
    CALL_DEBUG_ENTER;
    item.SetDisplayX(touchInfo.point.x);
    item.SetDisplayY(touchInfo.point.y);
    item.SetDisplayXPos(touchInfo.point.x);
    item.SetDisplayYPos(touchInfo.point.y);
    item.SetRawDisplayX(touchInfo.point.x);
    item.SetRawDisplayY(touchInfo.point.y);
    item.SetToolDisplayX(touchInfo.toolRect.point.x);
    item.SetToolDisplayY(touchInfo.toolRect.point.y);
    item.SetToolWidth(touchInfo.toolRect.width);
    item.SetToolHeight(touchInfo.toolRect.height);
}

#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
__attribute__((no_sanitize("cfi")))
void TouchTransformProcessor::NotifyFingersenseProcess(PointerEvent::PointerItem &pointerItem, int32_t &toolType)
{
    CALL_DEBUG_ENTER;
    TransformTouchProperties(rawTouch_, pointerItem);
    if (FINGERSENSE_WRAPPER->setCurrentToolType_) {
        MMI_HILOGD("Fingersense start classify touch down event");
        TouchType rawTouchTmp = rawTouch_;
        int32_t displayX = pointerItem.GetRawDisplayX();
        int32_t displayY = pointerItem.GetRawDisplayY();
#ifdef OHOS_BUILD_ENABLE_TOUCH
        WIN_MGR->ReverseXY(displayX, displayY);
#endif // OHOS_BUILD_ENABLE_TOUCH
        rawTouchTmp.x = displayX * DRIVER_NUMBER;
        rawTouchTmp.y = displayY * DRIVER_NUMBER;
        BytraceAdapter::StartToolType(toolType);
        FINGERSENSE_WRAPPER->setCurrentToolType_(rawTouchTmp, toolType);
        BytraceAdapter::StopToolType();
        FINGERSENSE_WRAPPER->SaveTouchInfo(rawTouchTmp.x, rawTouchTmp.y, toolType);
    }
}

void TouchTransformProcessor::TransformTouchProperties(TouchType &rawTouch, PointerEvent::PointerItem &pointerItem)
{
    CALL_DEBUG_ENTER;
    rawTouch.id = pointerItem.GetPointerId();
    rawTouch.pressure = pointerItem.GetPressure();
    rawTouch.x = pointerItem.GetRawDisplayX();
    rawTouch.y = pointerItem.GetRawDisplayY();
}
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER

bool TouchTransformProcessor::OnEventTouchMotion(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto touch = libinput_event_get_touch_event(event);
    CHKPF(touch);
    uint64_t time = libinput_event_touch_get_time_usec(touch);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    EventTouch touchInfo;
    int32_t logicalDisplayId = pointerEvent_->GetTargetDisplayId();
    if (!WIN_MGR->TouchPointToDisplayPoint(deviceId_, touch, touchInfo, logicalDisplayId, true)) {
        processedCount_++;
        if (processedCount_ == PRINT_INTERVAL_COUNT) {
            MMI_HILOGE("Get TouchMotionPointToDisplayPoint failed");
            processedCount_ = 0;
        }
        return false;
    }
    PointerEvent::PointerItem item;
    int32_t seatSlot = libinput_event_touch_get_seat_slot(touch);
    if (!(pointerEvent_->GetPointerItem(seatSlot, item))) {
        MMI_HILOGE("Get pointer parameter failed");
        return false;
    }
    int32_t blobId = libinput_event_touch_get_blob_id(touch);
    item.SetBlobId(blobId);
    double pressure = libinput_event_touch_get_pressure(touch);
    int32_t moveFlag = libinput_event_touch_get_move_flag(touch);
    int32_t longAxis = libinput_event_get_touch_contact_long_axis(touch);
    if (static_cast<uint32_t>(longAxis) & TOUCH_CANCEL_MASK) {
        pointerItemCancelMarks_.emplace(seatSlot, true);
    }
    int32_t shortAxis = libinput_event_get_touch_contact_short_axis(touch);
    item.SetMoveFlag(moveFlag);
    item.SetPressure(pressure);
    item.SetLongAxis(longAxis);
    item.SetShortAxis(shortAxis);
    item.SetDisplayX(touchInfo.point.x);
    item.SetDisplayY(touchInfo.point.y);
    item.SetDisplayXPos(touchInfo.point.x);
    item.SetDisplayYPos(touchInfo.point.y);
    item.SetRawDisplayX(touchInfo.point.x);
    item.SetRawDisplayY(touchInfo.point.y);
    item.SetToolDisplayX(touchInfo.toolRect.point.x);
    item.SetToolDisplayY(touchInfo.toolRect.point.y);
    item.SetToolWidth(touchInfo.toolRect.width);
    item.SetToolHeight(touchInfo.toolRect.height);
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);
    pointerEvent_->ClearFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    return true;
}
__attribute__((no_sanitize("cfi")))
bool TouchTransformProcessor::OnEventTouchUp(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto touch = libinput_event_get_touch_event(event);
    CHKPF(touch);
    uint64_t time = libinput_event_touch_get_time_usec(touch);
    pointerEvent_->SetActionTime(time);
    int32_t seatSlot = libinput_event_touch_get_seat_slot(touch);
    if (pointerItemCancelMarks_.find(seatSlot) != pointerItemCancelMarks_.end()) {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
        pointerItemCancelMarks_.erase(seatSlot);
    } else {
        pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    }
    
    PointerEvent::PointerItem item;
    if (!(pointerEvent_->GetPointerItem(seatSlot, item))) {
        MMI_HILOGE("Get pointer parameter failed");
        return false;
    }
    item.SetPressed(false);
#ifdef OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    auto keyHandler = InputHandler->GetKeyCommandHandler();
    if (keyHandler != nullptr && (!keyHandler->SkipKnuckleDetect())) {
        TransformTouchProperties(rawTouch_, item);
        if (FINGERSENSE_WRAPPER->notifyTouchUp_) {
            MMI_HILOGD("Notify fingersense touch up event");
            TouchType rawTouchTmp = rawTouch_;
            int32_t displayX = item.GetRawDisplayX();
            int32_t displayY = item.GetRawDisplayY();
#ifdef OHOS_BUILD_ENABLE_TOUCH
            WIN_MGR->ReverseXY(displayX, displayY);
#endif // OHOS_BUILD_ENABLE_TOUCH
            rawTouchTmp.x = displayX * DRIVER_NUMBER;
            rawTouchTmp.y = displayY * DRIVER_NUMBER;
            BytraceAdapter::StartTouchUp(item.GetPointerId());
            FINGERSENSE_WRAPPER->notifyTouchUp_(&rawTouchTmp);
            BytraceAdapter::StopTouchUp();
        }
    } else {
        MMI_HILOGD("Skip fingersense detect");
    }
#endif // OHOS_BUILD_ENABLE_FINGERSENSE_WRAPPER
    pointerEvent_->UpdatePointerItem(seatSlot, item);
    pointerEvent_->SetPointerId(seatSlot);
    pointerEvent_->ClearFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    return true;
}

bool TouchTransformProcessor::DumpInner()
{
    static int32_t lastDeviceId = -1;
    static std::string lastDeviceName("default");
    auto nowId = pointerEvent_->GetDeviceId();
    if (lastDeviceId != nowId) {
        auto device = INPUT_DEV_MGR->GetInputDevice(nowId);
        CHKPF(device);
        lastDeviceId = nowId;
        lastDeviceName = device->GetName();
    }
    WIN_MGR->UpdateTargetPointer(pointerEvent_);
    if (pointerEvent_->GetPointerAction() != PointerEvent::POINTER_ACTION_MOVE &&
        pointerEvent_->GetPointerAction() != PointerEvent::POINTER_ACTION_SWIPE_UPDATE) {
        aggregator_.Record(MMI_LOG_FREEZE, lastDeviceName + ", TW: " +
            std::to_string(pointerEvent_->GetTargetWindowId()), std::to_string(pointerEvent_->GetId()));
    }
    return true;
}

std::shared_ptr<PointerEvent> TouchTransformProcessor::OnEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPP(event);
    if (pointerEvent_ == nullptr) {
        pointerEvent_ = PointerEvent::Create();
        CHKPP(pointerEvent_);
    }
    auto type = libinput_event_get_type(event);
    uint64_t sensorTime = libinput_event_get_sensortime(event);
    pointerEvent_->SetSensorInputTime(sensorTime);
    switch (type) {
        case LIBINPUT_EVENT_TOUCH_DOWN: {
            CHKFR(OnEventTouchDown(event), nullptr, "Get OnEventTouchDown failed");
            break;
        }
        case LIBINPUT_EVENT_TOUCH_UP: {
            CHKFR(OnEventTouchUp(event), nullptr, "Get OnEventTouchUp failed");
            break;
        }
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            CHKFR(OnEventTouchMotion(event), nullptr, "Get OnEventTouchMotion failed");
            break;
        }
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
        case LIBINPUT_EVENT_TOUCH_CANCEL: {
            CHKFR(OnEventTouchCancel(event), nullptr, "Get OnEventTouchCancel failed");
            break;
        }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
        default: {
            MMI_HILOGE("Unknown event type, touchType:%{public}d", type);
            return nullptr;
        }
    }
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent_->UpdateId();
    pointerEvent_->AddFlag(InputEvent::EVENT_FLAG_GENERATE_FROM_REAL);
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
    if (!DumpInner()) {
        return nullptr;
    }
    EventLogHelper::PrintEventData(pointerEvent_, pointerEvent_->GetPointerAction(),
        pointerEvent_->GetPointerIds().size(), MMI_LOG_FREEZE);
    WIN_MGR->DrawTouchGraphic(pointerEvent_);
    return pointerEvent_;
}

int32_t TouchTransformProcessor::GetTouchToolType(struct libinput_event_touch *data,
    struct libinput_device *device)
{
    int32_t toolType = libinput_event_touch_get_tool_type(data);
    switch (toolType) {
        case MT_TOOL_NONE: {
            return GetTouchToolType(device);
        }
        case MT_TOOL_FINGER: {
            return PointerEvent::TOOL_TYPE_FINGER;
        }
        case MT_TOOL_PEN: {
            return PointerEvent::TOOL_TYPE_PEN;
        }
        default : {
            MMI_HILOGW("Unknown tool type, identified as finger, toolType:%{public}d", toolType);
            return PointerEvent::TOOL_TYPE_FINGER;
        }
    }
}

int32_t TouchTransformProcessor::GetTouchToolType(struct libinput_device *device)
{
    for (const auto &item : vecToolType_) {
        if (libinput_device_touch_btn_tool_type_down(device, item.first) == BTN_DOWN) {
            return item.second;
        }
    }
    MMI_HILOGD("Unknown Btn tool type, identified as finger");
    return PointerEvent::TOOL_TYPE_FINGER;
}

void TouchTransformProcessor::InitToolTypes()
{
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_PEN, PointerEvent::TOOL_TYPE_PEN));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_RUBBER, PointerEvent::TOOL_TYPE_RUBBER));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_BRUSH, PointerEvent::TOOL_TYPE_BRUSH));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_PENCIL, PointerEvent::TOOL_TYPE_PENCIL));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_AIRBRUSH, PointerEvent::TOOL_TYPE_AIRBRUSH));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_FINGER, PointerEvent::TOOL_TYPE_FINGER));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_MOUSE, PointerEvent::TOOL_TYPE_MOUSE));
    vecToolType_.emplace_back(std::make_pair(BTN_TOOL_LENS, PointerEvent::TOOL_TYPE_LENS));
}
} // namespace MMI
} // namespace OHOS
