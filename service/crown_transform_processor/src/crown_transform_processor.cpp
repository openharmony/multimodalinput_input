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

#include "crown_transform_processor.h"

#include <cinttypes>
#include <functional>

#include "define_multimodal.h"
#include "event_log_helper.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "timer_manager.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "CrownTransformProcessor"

namespace OHOS {
namespace MMI {
namespace {
const std::string CROWN_SOURCE { "rotary_crown" };
const std::string VIRTUAL_CROWN_SOURCE { "Virtual Crown" };
constexpr double DEGREE_ZERO { 0.0 };
constexpr double VELOCITY_ZERO { 0.0 };
constexpr double SCALE_RATIO = static_cast<double>(360) / 532;
constexpr uint64_t MICROSECONDS_PER_SECOND = 1000 * 1000;
}

CrownTransformProcessor::CrownTransformProcessor()
    : pointerEvent_(PointerEvent::Create())
{}

CrownTransformProcessor::~CrownTransformProcessor()
{}

std::shared_ptr<PointerEvent> CrownTransformProcessor::GetPointerEvent() const
{
    return pointerEvent_;
}

bool CrownTransformProcessor::IsCrownEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPF(event);
    auto device = libinput_event_get_device(event);
    CHKPF(device);
    std::string name = libinput_device_get_name(device);
    if (name == CROWN_SOURCE || name == VIRTUAL_CROWN_SOURCE) {
        auto type = libinput_event_get_type(event);
        if (type == LIBINPUT_EVENT_POINTER_AXIS) {
            struct libinput_event_pointer *pointerEvent = libinput_event_get_pointer_event(event);
            CHKPF(pointerEvent);
            auto source = libinput_event_pointer_get_axis_source(pointerEvent);
            if (source != LIBINPUT_POINTER_AXIS_SOURCE_WHEEL) {
                MMI_HILOGD("Not crown event, axis source:%{public}d", source);
                return false;
            }
            return true;
        } else {
            MMI_HILOGD("Not crown event, type:%{public}d", type);
            return false;
        }
    }
    
    MMI_HILOGD("Not crown event, device name:%{public}s", name.c_str());
    return false;
}

int32_t CrownTransformProcessor::NormalizeRotateEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);

    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    if (deviceId < 0) {
        MMI_HILOGE("The deviceId is invalid, deviceId:%{public}d", deviceId);
        return RET_ERR;
    }
    deviceId_ = deviceId;

    struct libinput_event_pointer *rawPointerEvent = libinput_event_get_pointer_event(event);
    CHKPR(rawPointerEvent, ERROR_NULL_POINTER);
    libinput_pointer_axis_source source = libinput_event_pointer_get_axis_source(rawPointerEvent);
    if (source == LIBINPUT_POINTER_AXIS_SOURCE_WHEEL) {
        if (TimerMgr->IsExist(timerId_)) {
            HandleCrownRotateUpdate(rawPointerEvent);
            TimerMgr->ResetTimer(timerId_);
        } else {
            static constexpr int32_t timeout = 100;
            std::weak_ptr<CrownTransformProcessor> weakPtr = shared_from_this();

            timerId_ = TimerMgr->AddTimer(timeout, 1, [weakPtr]() {
                CALL_DEBUG_ENTER;
                auto sharedProcessor = weakPtr.lock();
                CHKPV(sharedProcessor);
                sharedProcessor->timerId_ = -1;
                auto pointerEvent = sharedProcessor->GetPointerEvent();
                CHKPV(pointerEvent);
                sharedProcessor->HandleCrownRotateEnd();
                auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
                CHKPV(inputEventNormalizeHandler);
                inputEventNormalizeHandler->HandlePointerEvent(pointerEvent);
            });

            HandleCrownRotateBegin(rawPointerEvent);
        }

        auto inputEventNormalizeHandler = InputHandler->GetEventNormalizeHandler();
        CHKPR(inputEventNormalizeHandler, ERROR_NULL_POINTER);
        inputEventNormalizeHandler->HandlePointerEvent(pointerEvent_);
        DumpInner();
        return RET_OK;
    } else {
        MMI_HILOGE("The source is invalid, source:%{public}d", source);
        return RET_ERR;
    }
}

int32_t CrownTransformProcessor::HandleCrownRotateBegin(struct libinput_event_pointer *rawPointerEvent)
{
    CALL_DEBUG_ENTER;
    return HandleCrownRotateBeginAndUpdate(rawPointerEvent, PointerEvent::POINTER_ACTION_AXIS_BEGIN);
}

int32_t CrownTransformProcessor::HandleCrownRotateUpdate(struct libinput_event_pointer *rawPointerEvent)
{
    CALL_DEBUG_ENTER;
    return HandleCrownRotateBeginAndUpdate(rawPointerEvent, PointerEvent::POINTER_ACTION_AXIS_UPDATE);
}

int32_t CrownTransformProcessor::HandleCrownRotateEnd()
{
    CALL_DEBUG_ENTER;
    lastTime_ = 0;
    HandleCrownRotatePostInner(VELOCITY_ZERO, DEGREE_ZERO, PointerEvent::POINTER_ACTION_AXIS_END);
    return RET_OK;
}

int32_t CrownTransformProcessor::HandleCrownRotateBeginAndUpdate(struct libinput_event_pointer *rawPointerEvent,
    int32_t action)
{
    CALL_DEBUG_ENTER;
    CHKPR(rawPointerEvent, ERROR_NULL_POINTER);

    uint64_t currentTime = libinput_event_pointer_get_time_usec(rawPointerEvent);
    double scrollValue = libinput_event_pointer_get_axis_value_discrete(rawPointerEvent,
        LIBINPUT_POINTER_AXIS_SCROLL_VERTICAL);
    double degree = -scrollValue * SCALE_RATIO;
    double velocity = VELOCITY_ZERO;
    
    if (action == PointerEvent::POINTER_ACTION_AXIS_BEGIN) {
        lastTime_ = currentTime;
    } else if (action == PointerEvent::POINTER_ACTION_AXIS_UPDATE) {
        if (currentTime > lastTime_) {
            velocity = (degree * MICROSECONDS_PER_SECOND) / (currentTime - lastTime_);
        } else {
            degree = DEGREE_ZERO;
        }
        lastTime_ = currentTime;
    } else {
        MMI_HILOGE("The action is invalid, action:%{public}d", action);
        return RET_ERR;
    }

    MMI_HILOGD("Crown scrollValue:%{public}f, degree:%{public}f, velocity:%{public}f, currentTime:%{public}" PRId64
    " action:%{public}d", scrollValue, degree, velocity, currentTime, action);
    HandleCrownRotatePostInner(velocity, degree, action);
    return RET_OK;
}

void CrownTransformProcessor::HandleCrownRotatePostInner(double velocity, double degree, int32_t action)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);

    auto mouseInfo = WIN_MGR->GetMouseInfo();

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetDisplayX(mouseInfo.physicalX);
    pointerItem.SetDisplayY(mouseInfo.physicalY);
    pointerItem.SetWindowX(0);
    pointerItem.SetWindowY(0);
    pointerItem.SetPointerId(0);
    pointerItem.SetPressed(false);
    int64_t time = GetSysClockTime();
    pointerItem.SetDownTime(time);
    pointerItem.SetWidth(0);
    pointerItem.SetHeight(0);
    pointerItem.SetPressure(0);
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    pointerItem.SetDeviceId(deviceId_);
    pointerItem.SetRawDx(0);
    pointerItem.SetRawDy(0);

    pointerEvent_->UpdateId();
    pointerEvent_->UpdatePointerItem(pointerEvent_->GetPointerId(), pointerItem);
    pointerEvent_->SetVelocity(velocity);
    pointerEvent_->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, degree);
    pointerEvent_->SetPointerAction(action);
    pointerEvent_->SetActionTime(time);
    pointerEvent_->SetActionStartTime(time);
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_CROWN);
    pointerEvent_->SetButtonId(PointerEvent::BUTTON_NONE);
    pointerEvent_->SetPointerId(0);
    pointerEvent_->SetDeviceId(deviceId_);
    pointerEvent_->SetTargetDisplayId(mouseInfo.displayId);
    pointerEvent_->SetTargetWindowId(-1);
    pointerEvent_->SetAgentWindowId(-1);
    StartLogTraceId(pointerEvent_->GetId(), pointerEvent_->GetEventType(), pointerEvent_->GetPointerAction());
}

void CrownTransformProcessor::DumpInner()
{
    EventLogHelper::PrintEventData(pointerEvent_, MMI_LOG_HEADER);
    auto device = INPUT_DEV_MGR->GetInputDevice(pointerEvent_->GetDeviceId());
    CHKPV(device);
    MMI_HILOGI("The crown device id:%{public}d, event created by:%{public}s", pointerEvent_->GetId(),
        device->GetName().c_str());
}

void CrownTransformProcessor::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent_);
    mprintf(fd, "Crown device state information:\t");
    mprintf(fd,
            "PointerId:%{public}d | SourceType:%{public}s | PointerAction:%{public}s | ActionTime:%{public}llu"
            " | Velocity:%{public}f | AxisValue:%{public}f | AgentWindowId:%{public}d | TargetWindowId:%{public}d\t",
            pointerEvent_->GetPointerId(), pointerEvent_->DumpSourceType(), pointerEvent_->DumpPointerAction(),
            static_cast<unsigned long long>(pointerEvent_->GetActionTime()), pointerEvent_->GetVelocity(),
            pointerEvent_->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
            pointerEvent_->GetAgentWindowId(), pointerEvent_->GetTargetWindowId());
}
} // namespace MMI
} // namespace OHOS