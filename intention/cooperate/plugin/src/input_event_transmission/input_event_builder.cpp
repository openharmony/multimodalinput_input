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

#include "input_event_transmission/input_event_builder.h"

#include "display_info.h"

#include "cooperate_context.h"
#include "devicestatus_define.h"
#include "input_event_transmission/input_event_serialization.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "InputEventBuilder"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
namespace {
constexpr size_t LOG_PERIOD { 10 };
constexpr int32_t DEFAULT_SCREEN_WIDTH { 512 };
}

InputEventBuilder::InputEventBuilder(IContext *env)
    : env_(env)
{
    observer_ = std::make_shared<DSoftbusObserver>(*this);
    pointerEvent_ = MMI::PointerEvent::Create();
    keyEvent_ = MMI::KeyEvent::Create();
}

InputEventBuilder::~InputEventBuilder()
{
    Disable();
}

void InputEventBuilder::Enable(Context &context)
{
    CALL_INFO_TRACE;
    if (enable_) {
        return;
    }
    enable_ = true;
    xDir_ = 0;
    movement_ = 0;
    freezing_ = (context.CooperateFlag() & COOPERATE_FLAG_FREEZE_CURSOR);
    remoteNetworkId_ = context.Peer();
    env_->GetDSoftbus().AddObserver(observer_);
    Coordinate cursorPos = context.CursorPosition();
    FI_HILOGI("Cursor transite in (%{public}d, %{public}d)", cursorPos.x, cursorPos.y);
}

void InputEventBuilder::Disable()
{
    CALL_INFO_TRACE;
    if (enable_) {
        enable_ = false;
        env_->GetDSoftbus().RemoveObserver(observer_);
        ResetPressedEvents();
    }
}

void InputEventBuilder::Update(Context &context)
{
    remoteNetworkId_ = context.Peer();
    FI_HILOGI("Update peer to \'%{public}s\'", Utility::Anonymize(remoteNetworkId_).c_str());
}

void InputEventBuilder::Freeze()
{
    if (!enable_) {
        return;
    }
    xDir_ = 0;
    movement_ = 0;
    freezing_ = true;
    FI_HILOGI("Freeze remote input from '%{public}s'", Utility::Anonymize(remoteNetworkId_).c_str());
}

void InputEventBuilder::Thaw()
{
    if (!enable_) {
        return;
    }
    freezing_ = false;
    FI_HILOGI("Thaw remote input from '%{public}s'", Utility::Anonymize(remoteNetworkId_).c_str());
}

bool InputEventBuilder::OnPacket(const std::string &networkId, Msdp::NetPacket &packet)
{
    if (networkId != remoteNetworkId_) {
        FI_HILOGW("Unexpected packet from \'%{public}s\'", Utility::Anonymize(networkId).c_str());
        return false;
    }
    switch (packet.GetMsgId()) {
        case MessageId::DSOFTBUS_INPUT_POINTER_EVENT: {
            OnPointerEvent(packet);
            break;
        }
        case MessageId::DSOFTBUS_INPUT_KEY_EVENT: {
            OnKeyEvent(packet);
            break;
        }
        default: {
            FI_HILOGW("Unexpected message(%{public}d) from \'%{public}s\'",
                static_cast<int32_t>(packet.GetMsgId()), Utility::Anonymize(networkId).c_str());
            return false;
        }
    }
    return true;
}

void InputEventBuilder::OnPointerEvent(Msdp::NetPacket &packet)
{
    CHKPV(pointerEvent_);
    pointerEvent_->Reset();
    int32_t ret = InputEventSerialization::Unmarshalling(packet, pointerEvent_);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to deserialize pointer event");
        return;
    }
    if (!UpdatePointerEvent(pointerEvent_)) {
        return;
    }
    TagRemoteEvent(pointerEvent_);
    FI_HILOGI("PointerEvent(No:%{public}d,Source:%{public}s,Action:%{public}s)",
        pointerEvent_->GetId(), pointerEvent_->DumpSourceType(), pointerEvent_->DumpPointerAction());
    if (IsActive(pointerEvent_)) {
        env_->GetInput().SimulateInputEvent(pointerEvent_);
    }
}

void InputEventBuilder::OnKeyEvent(Msdp::NetPacket &packet)
{
    CHKPV(keyEvent_);
    pointerEvent_->Reset();
    int32_t ret = InputEventSerialization::NetPacketToKeyEvent(packet, keyEvent_);
    if (ret != RET_OK) {
        FI_HILOGE("Failed to deserialize key event");
        return;
    }
    FI_HILOGD("KeyEvent(No:%{public}d,Key:%{public}d,Action:%{public}d)",
        keyEvent_->GetId(), keyEvent_->GetKeyCode(), keyEvent_->GetKeyAction());
    env_->GetInput().SimulateInputEvent(keyEvent_);
}

bool InputEventBuilder::UpdatePointerEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    if (pointerEvent->GetSourceType() != MMI::PointerEvent::SOURCE_TYPE_MOUSE) {
        return true;
    }
    MMI::PointerEvent::PointerItem item;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
        FI_HILOGE("Corrupted pointer event");
        return false;
    }
    pointerEvent->AddFlag(MMI::InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    int64_t time = Utility::GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetActionStartTime(time);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(-1);
    pointerEvent->SetAgentWindowId(-1);
    return true;
}

void InputEventBuilder::TagRemoteEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    pointerEvent->SetDeviceId(
        (pointerEvent->GetDeviceId() >= 0) ?
        -(pointerEvent->GetDeviceId() + 1) :
        pointerEvent->GetDeviceId());
}

bool InputEventBuilder::IsActive(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    if (!freezing_) {
        return true;
    }
    if ((pointerEvent->GetSourceType() != MMI::PointerEvent::SOURCE_TYPE_MOUSE) ||
        ((pointerEvent->GetPointerAction() != MMI::PointerEvent::POINTER_ACTION_MOVE) &&
         (pointerEvent->GetPointerAction() != MMI::PointerEvent::POINTER_ACTION_PULL_MOVE))) {
        return true;
    }
    MMI::PointerEvent::PointerItem item;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
        FI_HILOGE("Corrupted pointer event");
        return false;
    }
    movement_ += item.GetRawDx();
    movement_ = std::clamp(movement_, -DEFAULT_SCREEN_WIDTH, DEFAULT_SCREEN_WIDTH);
    if (xDir_ == 0) {
        xDir_ = movement_;
    }
    if (((xDir_ > 0) && (movement_ <= 0)) || ((xDir_ < 0) && (movement_ >= 0))) {
        return true;
    }
    if ((nDropped_++ % LOG_PERIOD) == 0) {
        FI_HILOGI("Remote input from '%{public}s' is freezing", Utility::Anonymize(remoteNetworkId_).c_str());
    }
    return false;
}

void InputEventBuilder::ResetPressedEvents()
{
    CHKPV(env_);
    CHKPV(pointerEvent_);
    if (auto pressedButtons = pointerEvent_->GetPressedButtons(); !pressedButtons.empty()) {
        auto dragState = env_->GetDragManager().GetDragState();
        for (auto buttonId : pressedButtons) {
            if (dragState == DragState::START && buttonId == MMI::PointerEvent::MOUSE_BUTTON_LEFT) {
                FI_HILOGI("Dragging with mouse_button_left down, skip");
                continue;
            }
            pointerEvent_->SetButtonId(buttonId);
            pointerEvent_->SetPointerAction(MMI::PointerEvent::POINTER_ACTION_BUTTON_UP);
            env_->GetInput().SimulateInputEvent(pointerEvent_);
            FI_HILOGI("Simulate button-up event, buttonId:%{public}d", buttonId);
        }
        pointerEvent_->Reset();
    }
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
