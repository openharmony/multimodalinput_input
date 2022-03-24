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

#include "input_event.h"

#include <cassert>
#include <chrono>

#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
int64_t g_nextEventId = 1;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputEvent"};
} // namespace

InputEvent::InputEvent(int32_t eventType) : eventType_(eventType)
{
    Reset();
}

InputEvent::InputEvent(const InputEvent& other)
    : eventType_(other.eventType_), id_(other.id_), actionTime_(other.actionTime_),
    action_(other.action_), actionStartTime_(other.actionStartTime_),
    deviceId_(other.deviceId_), targetDisplayId_(other.targetDisplayId_),
    targetWindowId_(other.targetWindowId_), agentWindowId_(other.agentWindowId_),
    bitwise_(other.bitwise_), processedCallback_(other.processedCallback_)
{}

InputEvent::~InputEvent() {}

void InputEvent::Reset()
{
    struct timespec ts = { 0, 0 };
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        actionTime_ = 0;
    }
    id_ = -1;
    actionTime_ = (ts.tv_sec * 1000000 + (ts.tv_nsec / 1000));
    action_ = ACTION_UNKNOWN;
    actionStartTime_ = actionTime_;
    deviceId_ = -1;
    targetDisplayId_ = -1;
    targetWindowId_ = -1;
    agentWindowId_ = -1;
    bitwise_ = EVENT_FLAG_NONE;
}

std::shared_ptr<InputEvent> InputEvent::Create()
{
    auto event = std::shared_ptr<InputEvent>(new (std::nothrow) InputEvent(InputEvent::EVENT_TYPE_BASE));
    CHKPP(event);
    return event;
}

int32_t InputEvent::GetId() const
{
    return id_;
}

void InputEvent::SetId(int32_t id)
{
    id_ = id;
}

void InputEvent::UpdateId()
{
    id_ = g_nextEventId++;
}

int64_t InputEvent::GetActionTime() const
{
    return actionTime_;
}

void InputEvent::SetActionTime(int64_t actionTime)
{
    actionTime_ = actionTime;
}

int32_t InputEvent::GetAction() const
{
    return action_;
}

void InputEvent::SetAction(int32_t action)
{
    action_ = action;
}

int64_t InputEvent::GetActionStartTime() const
{
    return actionStartTime_;
}

void InputEvent::SetActionStartTime(int64_t actionStartTime)
{
    actionStartTime_ = actionStartTime;
}

int32_t InputEvent::GetDeviceId() const
{
    return deviceId_;
}

void InputEvent::SetDeviceId(int32_t deviceId)
{
    deviceId_ = deviceId;
}

int32_t InputEvent::GetTargetDisplayId() const
{
    return targetDisplayId_;
}

void InputEvent::SetTargetDisplayId(int32_t displayId)
{
    targetDisplayId_ = displayId;
}

int32_t InputEvent::GetAgentWindowId() const
{
    return agentWindowId_;
}

void InputEvent::SetAgentWindowId(int32_t windowId)
{
    agentWindowId_ = windowId;
}

int32_t InputEvent::GetTargetWindowId() const
{
    return targetWindowId_;
}

void InputEvent::SetTargetWindowId(int32_t windowId)
{
    targetWindowId_ = windowId;
}

int32_t InputEvent::GetEventType() const
{
    return eventType_;
}

const char* InputEvent::DumpEventType() const
{
    switch (eventType_) {
        case InputEvent::EVENT_TYPE_BASE:
            return "base";
        case InputEvent::EVENT_TYPE_KEY:
            return "key";
        case InputEvent::EVENT_TYPE_POINTER:
            return "pointer";
        case InputEvent::EVENT_TYPE_AXIS:
            return "axis";
        default:
            break;
    }
    return "unknown";
}

uint32_t InputEvent::GetFlag() const
{
    return bitwise_;
}

bool InputEvent::HasFlag(uint32_t flag)
{
    return (bitwise_ & flag) != 0;
}

void InputEvent::AddFlag(uint32_t flag)
{
    bitwise_ |= flag;
}

void InputEvent::ClearFlag()
{
    bitwise_ = EVENT_FLAG_NONE;
}

void InputEvent::SetProcessedCallback(std::function<void(int32_t)> callback)
{
    processedCallback_ = callback;
}

void InputEvent::MarkProcessed()
{
    if (!processedCallback_) {
        return;
    }
    auto func = processedCallback_;
    processedCallback_ = std::function<void(int32_t)>();
    func(id_);
}

bool InputEvent::WriteToParcel(Parcel &out) const
{
    if (!out.WriteInt32(eventType_)) {
        return false;
    }

    if (!out.WriteInt32(id_)) {
        return false;
    }

    if (!out.WriteInt64(actionTime_)) {
        return false;
    }

    if (!out.WriteInt32(action_)) {
        return false;
    }

    if (!out.WriteInt64(actionStartTime_)) {
        return false;
    }

    if (!out.WriteInt32(deviceId_)) {
        return false;
    }

    if (!out.WriteInt32(targetDisplayId_)) {
        return false;
    }

    if (!out.WriteInt32(targetWindowId_)) {
        return false;
    }

    if (!out.WriteInt32(agentWindowId_)) {
        return false;
    }

    if (!out.WriteUint32(bitwise_)) {
        return false;
    }

    return true;
}

bool InputEvent::ReadFromParcel(Parcel &in)
{
    if (!in.ReadInt32(eventType_)) {
        return false;
    }

    if (!in.ReadInt32(id_)) {
        return false;
    }

    if (!in.ReadInt64(actionTime_)) {
        return false;
    }

    if (!in.ReadInt32(action_)) {
        return false;
    }

    if (!in.ReadInt64(actionStartTime_)) {
        return false;
    }

    if (!in.ReadInt32(deviceId_)) {
        return false;
    }

    if (!in.ReadInt32(targetDisplayId_)) {
        return false;
    }

    if (!in.ReadInt32(targetWindowId_)) {
        return false;
    }

    if (!in.ReadInt32(agentWindowId_)) {
        return false;
    }

    if (!in.ReadUint32(bitwise_)) {
        return false;
    }

    return true;
}
} // namespace MMI
} // namespace OHOS
