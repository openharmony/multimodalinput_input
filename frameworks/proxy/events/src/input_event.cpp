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

#include "input_event.h"
#include <cassert>
#include <chrono>

namespace OHOS {
namespace MMI {
static int32_t g_nextEventId = 1;
const int32_t InputEvent::EVENT_TYPE_KEY;
const int32_t InputEvent::EVENT_TYPE_POINTER;
InputEvent::InputEvent(int32_t eventType) : eventType_(eventType)
{
    Init();
}

InputEvent::~InputEvent() {}

void InputEvent::Init()
{
    int32_t conversionStep = 1000000;
    struct timespec ts = { 0, 0 };
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        this->actionTime_ = 0;
    }
    id_ = DEFALUTID;
    uint64_t nowTime = (ts.tv_sec * static_cast<uint64_t>(1e3)) + (ts.tv_nsec / conversionStep);
    int32_t actionTime = static_cast<int32_t>(nowTime);
    this->actionTime_ = actionTime;
    this->action_ = ACTION_UNKNOWN;
    this->actionStartTime_ = actionTime_;
    this->deviceId_ = DEFALUTID;
    this->targetDisplayId_ = DEFALUTID;
    this->targetWindowId_ = DEFALUTID;
    this->agentWindowId_ = DEFALUTID;
    this->flag_ = 0;
}

std::shared_ptr<InputEvent> InputEvent::Create()
{
    return std::shared_ptr<InputEvent>(new InputEvent(InputEvent::EVENT_TYPE_BASE));
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

int32_t InputEvent::GetActionTime() const
{
    return actionTime_;
}

void InputEvent::SetActionTime(int32_t actionTime)
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

int32_t InputEvent::GetActionStartTime() const
{
    return actionStartTime_;
}

void InputEvent::SetActionStartTime(int32_t actionStartTime)
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

int32_t InputEvent::GetFlag() const
{
    return flag_;
}

bool InputEvent::HasFlag(int32_t flag)
{
    return (flag_ & flag) != 0;
}

void InputEvent::AddFlag(int32_t flag)
{
    flag_ |= flag;
}

void InputEvent::ClearFlag()
{
    flag_ = 0X00000000;
}

void InputEvent::SetProcessedCallback(std::function<void()> callback)
{
    processedCallback_ = callback;
}

void InputEvent::MarkProcessed()
{
    if (!processedCallback_) {
        return;
    }

    if (!processedCallback_) {
        return;
    }
    auto func = processedCallback_;
    processedCallback_ = std::function<void()>();
    func();
}

bool InputEvent::WriteToParcel(Parcel &out) const
{
    if (!out.WriteInt32(eventType_)) {
        return false;
    }

    if (!out.WriteInt32(id_)) {
        return false;
    }

    if (!out.WriteInt32(actionTime_)) {
        return false;
    }

    if (!out.WriteInt32(action_)) {
        return false;
    }

    if (!out.WriteInt32(actionStartTime_)) {
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

    if (!out.WriteInt32(flag_)) {
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

    if (!in.ReadInt32(actionTime_)) {
        return false;
    }

    if (!in.ReadInt32(action_)) {
        return false;
    }

    if (!in.ReadInt32(actionStartTime_)) {
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

    if (!in.ReadInt32(flag_)) {
        return false;
    }

    return true;
}
} // namespace MMI
} // namespace OHOS
