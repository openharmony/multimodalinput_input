/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <cinttypes>

#include "ffrt.h"
#include "ffrt_inner.h"

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "input_manager_impl.h"
#include "multimodal_input_connect_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_ANRDETECT
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ANRHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int64_t MAX_MARK_PROCESS_DELAY_TIME { 3500000 };
constexpr int64_t MIN_MARK_PROCESS_DELAY_TIME { 50000 };
constexpr int32_t INVALID_OR_PROCESSED_ID { -1 };
constexpr int32_t TIME_TRANSITION { 1000 };
constexpr int32_t PRINT_INTERVAL_COUNT { 30 };
} // namespace

ANRHandler::ANRHandler() {}

ANRHandler::~ANRHandler() {}

void ANRHandler::SetLastProcessedEventId(int32_t eventType, int32_t eventId, int64_t actionTime)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Processed event type:%{public}d, id:%{public}d, actionTime:%{public}" PRId64, eventType, eventId,
        actionTime);
    processedCount_++;
    if (processedCount_ == PRINT_INTERVAL_COUNT) {
        MMI_HILOG_FREEZEI("Last eventId:%{public}d, current eventId:%{public}d", lastEventId_, eventId);
        processedCount_ = 0;
        lastEventId_ = eventId;
    }
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
            MMI_HILOG_FREEZEI("Ffrt PE: %{public}s", idList.c_str());
            idList_.clear();
        }
    }
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->MarkProcessed(eventType, eventId);
    BytraceAdapter::StopMarkedTracker();
    if (ret != 0) {
        MMI_HILOGE("Send to server failed, ret:%{public}d", ret);
    }
}

void ANRHandler::SendEvent(int32_t eventType, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    auto task = [this, eventType, eventId] {
        MarkProcessed(eventType, eventId);
    };
    ffrt::submit(task, {}, {}, ffrt::task_attr().qos(ffrt_qos_deadline_request));
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