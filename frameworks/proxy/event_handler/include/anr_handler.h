/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ANR_HANDLER_H
#define ANR_HANDLER_H

#include <atomic>
#include <mutex>

#include "singleton.h"

#include "proto.h"

namespace OHOS {
namespace MMI {
class ANRHandler {
    DECLARE_DELAYED_SINGLETON(ANRHandler);

public:
    DISALLOW_COPY_AND_MOVE(ANRHandler);

    void SetLastProcessedEventId(int32_t eventType, int32_t eventId, int64_t actionTime);
    void MarkProcessed(int32_t eventType, int32_t eventId);
    void ResetAnrArray();
    std::mutex anrMtx_;

private:
    struct ANREvent {
        bool sendStatus{ false };
        int32_t lastEventId{ -1 };
        int32_t lastReportId{ -1 };
    };
    ANREvent event_[ANR_EVENT_TYPE_NUM];
    int32_t lastEventId_ { 0 };
    int32_t processedCount_ { 0 };
    std::vector<int32_t> idList_;
    void SendEvent(int32_t eventType, int32_t eventId);
    std::mutex mutex_;
};

#define ANRHDL ::OHOS::DelayedSingleton<ANRHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // ANR_HANDLER_H