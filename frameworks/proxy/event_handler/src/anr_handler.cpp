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

#include "define_multimodal.h"

#include "input_manager_impl.h"
#include "multimodal_input_connect_manager.h"
#include "ffrt.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ANRHandler" };
constexpr int64_t MAX_MARK_PROCESS_DELAY_TIME = 3500000;
constexpr int64_t MIN_MARK_PROCESS_DELAY_TIME = 50000;
constexpr int32_t INVALID_OR_PROCESSED_ID = -1;
constexpr int32_t TIME_TRANSITION = 1000;
} // namespace

ANRHandler::ANRHandler() {}

ANRHandler::~ANRHandler() {}

void ANRHandler::SetLastProcessedEventId(int32_t eventType, int32_t eventId, int64_t actionTime)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Processed event type:%{public}d, id:%{public}d, actionTime:%{public}" PRId64, eventType, eventId,
        actionTime);
    SendEvent(eventType, eventId);
}

void ANRHandler::MarkProcessed(int32_t eventType, int32_t eventId)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Processed event type:%{public}d, id:%{public}d", eventType, eventId);
    int32_t ret = MULTIMODAL_INPUT_CONNECT_MGR->MarkProcessed(eventType, eventId);
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
    ffrt::submit(task, {}, {}, ffrt::task_attr().qos(ffrt::qos_user_initiated));
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