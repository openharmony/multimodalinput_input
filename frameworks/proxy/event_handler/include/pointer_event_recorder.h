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

#ifndef POINTER_EVENT_RECORDER_H
#define POINTER_EVENT_RECORDER_H

#include <atomic>
#include <mutex>
#include <vector>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class PointerEventRecorder {
public:
    PointerEventRecorder() = default;
    ~PointerEventRecorder() = default;

    int32_t Enable(int32_t maxCount);
    int32_t Disable();
    int32_t Query(std::vector<std::shared_ptr<PointerEvent>> &pointerList);
    void PushEvent(const std::shared_ptr<PointerEvent> &event);

private:
    struct EventRecord {
        int32_t sourceType { 0 };
        int32_t toolType { 0 };
        int32_t deviceId { 0 };
        int32_t pointerAction { 0 };
        int64_t actionTime { 0 };
    };

    static constexpr int32_t MAX_RECORD_COUNT = 100;

    std::atomic<bool> enabled_ { false };
    std::mutex mutex_;
    std::vector<EventRecord> buffer_;
    int32_t capacity_ { 0 };
    int32_t head_ { 0 };
    int32_t tail_ { 0 };
    int32_t size_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // POINTER_EVENT_RECORDER_H
