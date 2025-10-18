/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "mmi_log.h"

#include "axis_event.h"
#include "key_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
struct LogTraceKey {
    int64_t traceId;
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
        if (item->traceId == -1) {
            continue;
        }
        if (item != g_traceIds.begin()) {
            g_traceStr += "/";
        }
        g_traceStr += Action2Str(item->evtType, item->action);
        g_traceStr += std::to_string(item->traceId);
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
    if (g_traceIds.size() <= iter->second) {
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
        while (!g_traceIds.empty() && g_traceIds.back().traceId == -1) {
            g_traceIds.pop_back();
        }
    } else {
        // can't erase it, erase it will make the index of other elem changed.
        LogTraceKey &toDelete = g_traceIds.at(idx);
        toDelete.traceId = -1;
    }
    RefreshTraceStr();
}

__attribute__((noinline)) const char *FormatLogTrace()
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
} // namespace MMI
} // namespace OHOS
