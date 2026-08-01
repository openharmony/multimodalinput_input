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

#include "pointer_event_recorder.h"

#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventRecorder"

namespace OHOS {
namespace MMI {
int32_t PointerEventRecorder::Enable(int32_t maxCount)
{
    if (maxCount <= 0) {
        MMI_HILOGE("Invalid maxCount:%{public}d", maxCount);
        return RET_ERR;
    }
    if (maxCount > MAX_RECORD_COUNT) {
        MMI_HILOGI("Clamp maxCount from %{public}d to %{public}d", maxCount, MAX_RECORD_COUNT);
        maxCount = MAX_RECORD_COUNT;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_.store(false);
    buffer_.resize(maxCount);
    capacity_ = maxCount;
    head_ = 0;
    tail_ = 0;
    size_ = 0;
    enabled_.store(true);
    MMI_HILOGI("Enable pointer event record, maxCount:%{public}d", maxCount);
    return RET_OK;
}

int32_t PointerEventRecorder::Disable()
{
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_.store(false);
    head_ = 0;
    tail_ = 0;
    size_ = 0;
    capacity_ = 0;
    buffer_.clear();
    buffer_.shrink_to_fit();
    MMI_HILOGI("Disable pointer event record");
    return RET_OK;
}

void PointerEventRecorder::PushEvent(const std::shared_ptr<PointerEvent> &event)
{
    CHKPV(event);
    if (!enabled_.load()) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!enabled_.load()) {
        return;
    }
    auto &record = buffer_[tail_];
    record.sourceType = event->GetSourceType();
    record.deviceId = event->GetDeviceId();
    record.pointerAction = event->GetPointerAction();
    record.actionTime = event->GetActionTime();
    record.pointerId = event->GetPointerId();
    record.itemPointerIds.clear();
    record.itemToolTypes.clear();
    std::list<PointerEvent::PointerItem> pointerItems = event->GetAllPointerItems();
    for (const auto &item : pointerItems) {
        record.itemPointerIds.push_back(item.GetPointerId());
        record.itemToolTypes.push_back(item.GetToolType());
    }
    tail_ = (tail_ + 1) % capacity_;
    if (size_ < capacity_) {
        size_++;
    } else {
        head_ = (head_ + 1) % capacity_;
    }
}

int32_t PointerEventRecorder::Query(std::vector<std::shared_ptr<PointerEvent>> &pointerList)
{
    std::lock_guard<std::mutex> lock(mutex_);
    pointerList.clear();
    for (int32_t i = 0; i < size_; ++i) {
        int32_t idx = (head_ + i) % capacity_;
        auto &record = buffer_[idx];
        auto pointerEvent = PointerEvent::Create();
        CHKPR(pointerEvent, RET_ERR);
        pointerEvent->SetSourceType(record.sourceType);
        pointerEvent->SetDeviceId(record.deviceId);
        pointerEvent->SetPointerAction(record.pointerAction);
        pointerEvent->SetActionTime(record.actionTime);
        pointerEvent->SetPointerId(record.pointerId);
        auto pidIt = record.itemPointerIds.begin();
        auto toolIt = record.itemToolTypes.begin();
        while (pidIt != record.itemPointerIds.end() && toolIt != record.itemToolTypes.end()) {
            PointerEvent::PointerItem item;
            item.SetPointerId(*pidIt);
            item.SetToolType(*toolIt);
            pointerEvent->AddPointerItem(item);
            ++pidIt;
            ++toolIt;
        }
        pointerList.push_back(pointerEvent);
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
