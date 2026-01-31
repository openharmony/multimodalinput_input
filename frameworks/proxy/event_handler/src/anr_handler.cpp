/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "anr_handler.h"

#include "ffrt_inner.h"

#include "bytrace_adapter.h"
#include "multimodal_input_connect_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_ANRDETECT
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ANRHandler"

namespace OHOS {
namespace MMI {
namespace {
[[ maybe_unused ]] constexpr int64_t MAX_MARK_PROCESS_DELAY_TIME { 3500000 };
[[ maybe_unused ]] constexpr int64_t MIN_MARK_PROCESS_DELAY_TIME { 50000 };
[[ maybe_unused ]] constexpr int32_t INVALID_OR_PROCESSED_ID { -1 };
[[ maybe_unused ]] constexpr int32_t TIME_TRANSITION { 1000 };
constexpr int32_t PRINT_INTERVAL_COUNT { 100 };
} // namespace

ANRHandler::ANRHandler() {}

ANRHandler::~ANRHandler() {}

void ANRHandler::SetLastProcessedEventId(int32_t eventType, int32_t eventId, int64_t actionTime)
{
    CALL_DEBUG_ENTER;
    if (eventId < 0) {
        MMI_HILOGD("eventId:%{public}d", eventId);
        return;
    }
    MMI_HILOGD("Processed event type:%{public}d, id:%{public}d, actionTime:%{public}" PRId64, eventType, eventId,
        actionTime);
    processedCount_++;
    if (processedCount_ == PRINT_INTERVAL_COUNT) {
        MMI_HILOGD("Last eventId:%{public}d, current eventId:%{public}d", lastEventId_, eventId);
        processedCount_ = 0;
    }
    lastEventId_ = eventId;
    SendEvent(eventType, eventId);
}

void ANRHandler::MarkProcessed(int32_t eventType, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    BytraceAdapter::StartMarkedTracker(eventId);
    MMI_HILOGD("Processed event type:%{public}d, id:%{public}d", eventType, eventId);
    {
        std::lock_guard<std::mutex> guard(mutex_);
        idList_.push_back(eventId);
        if (idList_.size() >= PRINT_INTERVAL_COUNT) {
            std::string idList = std::to_string(idList_.front()) + " " + std::to_string(idList_.back());
            MMI_HILOG_FREEZEI("Ffrt PE:%{public}s", idList.c_str());
            idList_.clear();
        }
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->MarkProcessed(eventType, eventId);
    BytraceAdapter::StopMarkedTracker();
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
    MarkProcessedPendingEvents(eventType, eventId);

    bool hasNewEvent = false;
    int32_t newEventId = -1;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (pendingEvents_[eventType] != -1) {
            hasNewEvent = true;
            newEventId = pendingEvents_[eventType];
            pendingEvents_[eventType] = -1; // 消费
        }
    }
 
    if (hasNewEvent) {
        // 重新提交任务处理新事件
        auto task = [this, eventType, newEventId] {
            MarkProcessed(eventType, newEventId);
        };
        ffrt::submit(task, {}, {}, ffrt::task_attr().qos(ffrt_qos_deadline_request));
    }
}

void ANRHandler::MarkProcessedPendingEvents(int32_t eventType, int32_t eventId)
{
    std::vector<std::pair<int32_t, int32_t>> pendingToProcess; // {eventType, eventId}
    {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto& kv : pendingEvents_) {
            int32_t type = kv.first;
            int32_t id = kv.second;
            if (id != -1) {
                pendingToProcess.emplace_back(type, id);
                kv.second = -1;
            }
        }
    }
    for (const auto& [type, id] : pendingToProcess) {
        if (type == eventType && id == eventId) {
            continue;
        }
        BytraceAdapter::StartMarkedTracker(id);
        int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->MarkProcessed(type, id);
        BytraceAdapter::StopMarkedTracker();
 
        if (ret != 0) {
            MMI_HILOGE("Send pending event (type:%{public}d, id:%{public}d) to server failed, ret:%{public}d",
                type, id, ret);
        }
    }
}

void ANRHandler::SetLastDispatchedEventId(int32_t eventId)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Dispatched event id:%{public}d", eventId);
    lastDispatchedEventId_.store(eventId);
}

void ANRHandler::SetLastProcessEventId(int32_t eventId)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Dispatched event id:%{public}d", eventId);
    lastProcessedEventId_.store(eventId);
}

void ANRHandler::GetLastEventIds(int32_t &markedId, int32_t &processedId, int32_t &dispatchedEventId)
{
    CALL_DEBUG_ENTER;
    markedId = lastEventId_;
    processedId = lastProcessedEventId_.load();
    dispatchedEventId = lastDispatchedEventId_.load();
    MMI_HILOGD("Get eventIds, markedId:%{public}d processedId:%{public}d dispatchedEventId:%{public}d",
        markedId, processedId, dispatchedEventId);
}

void ANRHandler::SendEvent(int32_t eventType, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    bool shouldSubmit = false;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (pendingEvents_.count(eventType) && pendingEvents_[eventType] != -1) {
            if (eventId > pendingEvents_[eventType]) {
                pendingEvents_[eventType] = eventId;
            }
            return;
        } else {
            pendingEvents_[eventType] = eventId;
            shouldSubmit = true;
        }
    }
    if (shouldSubmit) {
        auto task = [this, eventType, eventId] {
            MarkProcessed(eventType, eventId);
        };
        ffrt::submit(task, {}, {}, ffrt::task_attr().qos(ffrt_qos_deadline_request));
    }
}

void ANRHandler::ResetAnrArray()
{
    for (int i = 0; i < ANR_EVENT_TYPE_NUM; i++) {
        event_[i].sendStatus = false;
        event_[i].lastEventId = -1;
        event_[i].lastReportId = -1;
    }
}
} // namespace MMI
} // namespace OHOS