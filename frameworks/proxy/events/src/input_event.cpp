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

#include <cassert>
#include <chrono>

#include "axis_event.h"
#include "event_log_helper.h"
#include "input_event.h"
#include "key_event.h"
#include "mmi_log.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEvent"

namespace OHOS {
namespace MMI {
namespace {
int64_t g_nextEventId = 1;
constexpr uint32_t DATA_LENGTH_LIMIT { 1024 }; // 1024: max length
} // namespace

thread_local std::string  EventLogHelper::userType_ = "";

InputEvent::InputEvent(int32_t eventType) : eventType_(eventType)
{
    Reset();
}

InputEvent::InputEvent(const InputEvent& other)
    : eventType_(other.eventType_), id_(other.id_), actionTime_(other.actionTime_),
      action_(other.action_), actionStartTime_(other.actionStartTime_),
      deviceId_(other.deviceId_), targetDisplayId_(other.targetDisplayId_),
      targetWindowId_(other.targetWindowId_), agentWindowId_(other.agentWindowId_),
      bitwise_(other.bitwise_), markEnabled_(other.markEnabled_), processedCallback_(other.processedCallback_) {}

InputEvent::~InputEvent() {}

void InputEvent::Reset()
{
    struct timespec ts = { 0, 0 };
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        actionTime_ = 0;
    }
    id_ = -1;
    if (!AddInt64(ts.tv_sec * 1000000, ts.tv_nsec / 1000, actionTime_)) {
        MMI_HILOGE("The addition of actionTime_ overflows");
        return;
    }
    action_ = ACTION_UNKNOWN;
    actionStartTime_ = actionTime_;
    deviceId_ = -1;
    targetDisplayId_ = -1;
    targetWindowId_ = -1;
    agentWindowId_ = -1;
    bitwise_ = EVENT_FLAG_NONE;
    markEnabled_ = true;
}

std::shared_ptr<InputEvent> InputEvent::Create()
{
    auto event = std::shared_ptr<InputEvent>(new (std::nothrow) InputEvent(InputEvent::EVENT_TYPE_BASE));
    CHKPP(event);
    return event;
}

const char* InputEvent::EventTypeToString(int32_t eventType)
{
    switch (eventType) {
        case InputEvent::EVENT_TYPE_BASE: {
            return "base";
        }
        case InputEvent::EVENT_TYPE_KEY: {
            return "key";
        }
        case InputEvent::EVENT_TYPE_POINTER: {
            return "pointer";
        }
        case InputEvent::EVENT_TYPE_AXIS: {
            return "axis";
        }
        case InputEvent::EVENT_TYPE_FINGERPRINT: {
            return "fingerprint";
        }
        default: {
            MMI_HILOGW("Unknown EVENT_TYPE");
            return "unknown";
        }
    }
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

void InputEvent::SetSensorInputTime(uint64_t sensorInputTime)
{
    sensorInputTime_ = sensorInputTime;
}

uint64_t InputEvent::GetSensorInputTime()
{
    return sensorInputTime_;
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

void InputEvent::ClearFlag(uint32_t flag)
{
    bitwise_ &= (~flag);
}

bool InputEvent::IsMarkEnabled() const
{
    return markEnabled_;
}


void InputEvent::SetMarkEnabled(bool markEnabled)
{
    markEnabled_ = markEnabled;
}


void InputEvent::SetProcessedCallback(std::function<void(int32_t, int64_t)> callback)
{
    processedCallback_ = callback;
}

void InputEvent::MarkProcessed()
{
    if (!processedCallback_) {
        return;
    }
    if (!markEnabled_) {
        MMI_HILOGD("Skip MarkProcessed eventId:%{public}d, eventType:%{public}d", id_, eventType_);
        return;
    }
    auto func = processedCallback_;
    processedCallback_ = std::function<void(int32_t, int64_t)>();
    func(id_, actionTime_);
}

void InputEvent::SetExtraData(const std::shared_ptr<const uint8_t[]> data, uint32_t length)
{
    if (data && (length > 0) && (length <= DATA_LENGTH_LIMIT)) {
        extraData_ = data;
        extraDataLength_ = length;
    }
}

void InputEvent::GetExtraData(std::shared_ptr<const uint8_t[]> &data, uint32_t &length) const
{
    if (extraData_ && extraDataLength_ != 0) {
        data = extraData_;
        length = extraDataLength_;
    } else {
        length = 0;
    }
}

bool InputEvent::WriteToParcel(Parcel &out) const
{
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    return false;
#endif
    WRITEINT32(out, eventType_);
    WRITEINT32(out, id_);
    WRITEINT64(out, actionTime_);
    WRITEUINT64(out, sensorInputTime_);
    WRITEINT32(out, action_);
    WRITEINT64(out, actionStartTime_);
    WRITEINT32(out, deviceId_);
    WRITEINT32(out, targetDisplayId_);
    WRITEINT32(out, targetWindowId_);
    WRITEINT32(out, agentWindowId_);
    WRITEUINT32(out, bitwise_);
    WRITEBOOL(out, markEnabled_);
    if (extraData_ && extraDataLength_ != 0) {
        WRITEUINT32(out, extraDataLength_);
        WRITEBUFFER(out, (void *)extraData_.get(), extraDataLength_);
    } else {
        WRITEUINT32(out, 0);
    }
    return true;
}

bool InputEvent::ReadFromParcel(Parcel &in)
{
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    return false;
#endif
    READINT32(in, eventType_);
    READINT32(in, id_);
    READINT64(in, actionTime_);
    READUINT64(in, sensorInputTime_);
    READINT32(in, action_);
    READINT64(in, actionStartTime_);
    READINT32(in, deviceId_);
    READINT32(in, targetDisplayId_);
    READINT32(in, targetWindowId_);
    READINT32(in, agentWindowId_);
    READUINT32(in, bitwise_);
    READBOOL(in, markEnabled_);
    READUINT32(in, extraDataLength_);

    if (extraDataLength_ == 0) {
        return true;
    }
    if (extraDataLength_ > DATA_LENGTH_LIMIT) {
        extraDataLength_ = 0;
        return false;
    }
    const uint8_t *buffer = in.ReadBuffer(extraDataLength_);
    if (buffer == nullptr) {
        extraDataLength_ = 0;
        return false;
    }
    std::shared_ptr<uint8_t[]> sp(new uint8_t[extraDataLength_], [](uint8_t* ptr) { delete[] ptr; });
    if (sp == nullptr) {
        extraDataLength_ = 0;
        return false;
    }
    std::copy(buffer, buffer + extraDataLength_, sp.get());
    extraData_ = sp;
    return true;
}

std::string_view InputEvent::ActionToShortStr(int32_t action)
{
    switch (action) {
        case InputEvent::ACTION_CANCEL:
            return "B:C:";
        case InputEvent::ACTION_UNKNOWN:
            return "B:UK:";
        default:
            return "B:?:";
    }
}

struct LogTraceKey {
    int64_t Id;
    int32_t action;
    int32_t evtType;
};

thread_local std::vector<LogTraceKey> g_traceIds;
thread_local std::unordered_map<int64_t, size_t> g_traceIdToIdx;
thread_local std::string g_traceStr;

std::string_view Action2Str(int32_t eventType, int32_t action)
{
    switch (eventType) {
        case InputEvent::EVENT_TYPE_KEY: {
            return KeyEvent::ActionToShortStr(action);
        }
        case InputEvent::EVENT_TYPE_POINTER:
        case InputEvent::EVENT_TYPE_FINGERPRINT: {
            return PointerEvent::ActionToShortStr(action);
        }
        case InputEvent::EVENT_TYPE_AXIS: {
            return AxisEvent::ActionToShortStr(action);
        }
        case InputEvent::EVENT_TYPE_BASE: {
            return InputEvent::ActionToShortStr(action);
        }
        default: {
            return "?:?:";
        }
    }
}

void RefreshTraceStr()
{
    g_traceStr.clear();
    for (auto item = g_traceIds.begin(); item < g_traceIds.end(); ++item) {
        if (item != g_traceIds.begin()) {
            g_traceStr += "/";
        }
        g_traceStr += Action2Str(item->evtType, item->action);
        g_traceStr += std::to_string(item->Id);
    }
}

void StartLogTraceId(int64_t traceId, int32_t eventType, int32_t action)
{
    if (traceId == -1) {
        return;
    }
    auto iter = g_traceIdToIdx.find(traceId);
    if (iter == g_traceIdToIdx.end()) {
        g_traceIds.push_back({traceId, action, eventType});
        g_traceIdToIdx.emplace(traceId, g_traceIds.size() - 1);
        std::string currentTraceStr(Action2Str(eventType, action));
        currentTraceStr += std::to_string(traceId);
        if (g_traceIds.size() == 1) {
            g_traceStr = currentTraceStr;
        } else {
            g_traceStr += "/" + currentTraceStr;
        }
        return;
    }
    LogTraceKey &old = g_traceIds.at(iter->second);
    if (old.evtType != eventType || old.action != action) {
        old.evtType = eventType;
        old.action = action;
        RefreshTraceStr();
    }
};

void EndLogTraceId(int64_t id)
{
    auto iter = g_traceIdToIdx.find(id);
    if (iter == g_traceIdToIdx.end()) {
        return;
    }
    size_t idx = iter->second;
    g_traceIdToIdx.erase(iter);
    size_t idCount = g_traceIds.size();
    if (idCount <= idx) {
        return;
    }

    if (idCount == idx + 1) {
        g_traceIds.pop_back();
    } else {
        auto item = g_traceIds.begin();
        item += idx;
        g_traceIds.erase(item);
    }
    RefreshTraceStr();
}

const char *FormatLogTrace()
{
    return g_traceStr.c_str();
}


void ResetLogTrace()
{
    g_traceIds.clear();
    g_traceIdToIdx.clear();
    g_traceStr.clear();
}

LogTracer::LogTracer(int64_t traceId, int32_t evtType, int32_t action)
{
    traceId_ = traceId;
    StartLogTraceId(traceId, evtType, action);
}

LogTracer::~LogTracer()
{
    EndLogTraceId(traceId_);
}

LogTracer::LogTracer()
{
    traceId_ = -1;
}

LogTracer::LogTracer(LogTracer &&other) noexcept: traceId_(other.traceId_)
{
    other.traceId_ = -1;
}

LogTracer &LogTracer::operator=(LogTracer &&other) noexcept
{
    if (this != &other) {
        traceId_ = other.traceId_;
        other.traceId_ = -1;
    }
    return *this;
}

int32_t OHOS::MMI::EventLogHelper::infoDictCount_ = 0;
int32_t OHOS::MMI::EventLogHelper::debugDictCount_ = 0;

} // namespace MMI
} // namespace OHOS
