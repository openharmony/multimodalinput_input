/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "input_event_transmission/input_event_interceptor.h"

#include "cooperate_context.h"
#include "devicestatus_define.h"
#include "display_manager.h"
#include "input_event_transmission/input_event_serialization.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "InputEventInterceptor"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
std::set<int32_t> InputEventInterceptor::filterKeys_ {
    MMI::KeyEvent::KEYCODE_BACK,
    MMI::KeyEvent::KEYCODE_VOLUME_UP,
    MMI::KeyEvent::KEYCODE_VOLUME_DOWN,
    MMI::KeyEvent::KEYCODE_POWER,
};

std::set<int32_t> InputEventInterceptor::filterPointers_ {
    MMI::PointerEvent::POINTER_ACTION_ENTER_WINDOW,
    MMI::PointerEvent::POINTER_ACTION_LEAVE_WINDOW,
    MMI::PointerEvent::POINTER_ACTION_PULL_IN_WINDOW,
    MMI::PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW,
};

InputEventInterceptor::~InputEventInterceptor()
{
    Disable();
}

void InputEventInterceptor::Enable(Context &context)
{
    CALL_INFO_TRACE;
    if (interceptorId_ > 0) {
        return;
    }
    auto cursorPos = context.CursorPosition();
    FI_HILOGI("Cursor transite out at (%{public}d, %{public}d)", cursorPos.x, cursorPos.y);
    remoteNetworkId_ = context.Peer();
    sender_ = context.Sender();
    interceptorId_ = env_->GetInput().AddInterceptor(
        [this](std::shared_ptr<MMI::PointerEvent> pointerEvent) { this->OnPointerEvent(pointerEvent); },
        [this](std::shared_ptr<MMI::KeyEvent> keyEvent) { this->OnKeyEvent(keyEvent); });
    if (interceptorId_ < 0) {
        FI_HILOGE("Input::AddInterceptor fail");
    }
}

void InputEventInterceptor::Disable()
{
    CALL_INFO_TRACE;
    if (interceptorId_ > 0) {
        env_->GetInput().RemoveInterceptor(interceptorId_);
        interceptorId_ = -1;
    }
}

void InputEventInterceptor::Update(Context &context)
{
    remoteNetworkId_ = context.Peer();
    FI_HILOGI("Update peer to \'%{public}s\'", Utility::Anonymize(remoteNetworkId_).c_str());
}

void InputEventInterceptor::OnPointerEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (auto pointerAction = pointerEvent->GetPointerAction();
        filterPointers_.find(pointerAction) != filterPointers_.end()) {
        FI_HILOGI("Current pointerAction:%{public}d, skip", static_cast<int32_t>(pointerAction));
        return;
    }
    if (auto pointerAction = pointerEvent->GetPointerAction();
        pointerAction == MMI::PointerEvent::POINTER_ACTION_CANCEL) {
        auto originAction = pointerEvent->GetOriginPointerAction();
        FI_HILOGI("Reset to origin action:%{public}d", static_cast<int32_t>(originAction));
        pointerEvent->SetPointerAction(originAction);
    }
    NetPacket packet(MessageId::DSOFTBUS_INPUT_POINTER_EVENT);

    int32_t ret = InputEventSerialization::Marshalling(pointerEvent, packet);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to serialize pointer event");
        return;
    }
    FI_HILOGI("PointerEvent(No:%{public}d,Source:%{public}s,Action:%{public}s)",
        pointerEvent->GetId(), pointerEvent->DumpSourceType(), pointerEvent->DumpPointerAction());
    env_->GetDSoftbus().SendPacket(remoteNetworkId_, packet);
}

void InputEventInterceptor::OnKeyEvent(std::shared_ptr<MMI::KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    if (filterKeys_.find(keyEvent->GetKeyCode()) != filterKeys_.end()) {
        keyEvent->AddFlag(MMI::AxisEvent::EVENT_FLAG_NO_INTERCEPT);
        env_->GetInput().SimulateInputEvent(keyEvent);
        return;
    }
    NetPacket packet(MessageId::DSOFTBUS_INPUT_KEY_EVENT);

    int32_t ret = InputEventSerialization::KeyEventToNetPacket(keyEvent, packet);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to serialize key event");
        return;
    }
    FI_HILOGD("KeyEvent(No:%{public}d,Key:%{public}d,Action:%{public}d)",
        keyEvent->GetId(), keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
    env_->GetDSoftbus().SendPacket(remoteNetworkId_, packet);
}

void InputEventInterceptor::ReportPointerEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    MMI::PointerEvent::PointerItem pointerItem;

    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        FI_HILOGE("Corrupted pointer event");
        return;
    }
    auto ret = sender_.Send(CooperateEvent(
        CooperateEventType::INPUT_POINTER_EVENT,
        InputPointerEvent {
            .deviceId = pointerEvent->GetDeviceId(),
            .pointerAction = pointerEvent->GetPointerAction(),
            .sourceType = pointerEvent->GetSourceType(),
            .position = Coordinate {
                .x = pointerItem.GetDisplayX(),
                .y = pointerItem.GetDisplayY(),
            }
        }));
    if (ret != Channel<CooperateEvent>::NO_ERROR) {
        FI_HILOGE("Failed to send event via channel, error:%{public}d", ret);
    }
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
