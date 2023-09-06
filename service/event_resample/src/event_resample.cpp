/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "event_resample.h"

#include "event_log_helper.h"
#include "mmi_log.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL { LOG_CORE, MMI_LOG_DOMAIN, "EventResample" };

// Microseconds per milliseconds.
constexpr int64_t US_PER_MS = 1000;

// Latency added during resampling.  A few milliseconds doesn't hurt much but
// reduces the impact of mispredicted touch positions.
constexpr int64_t RESAMPLE_LATENCY = 5 * US_PER_MS;

// Minimum time difference between consecutive samples before attempting to resample.
constexpr int64_t RESAMPLE_MIN_DELTA = 2 * US_PER_MS;

// Maximum time difference between consecutive samples before attempting to resample
// by extrapolation.
constexpr int64_t RESAMPLE_MAX_DELTA = 20 * US_PER_MS;

// Maximum time to predict forward from the last known state, to avoid predicting too
// far into the future.
constexpr int64_t RESAMPLE_MAX_PREDICTION = 4 * US_PER_MS;
} // namespace

EventResample::EventResample(){};
EventResample::~EventResample(){};

std::shared_ptr<PointerEvent> EventResample::onEventConsume(std::shared_ptr<PointerEvent> pointerEvent, int64_t frameTime, bool &deferred, ErrCode &status)
{
    int32_t pointerAction = PointerEvent::POINTER_ACTION_UNKNOWN;
    MotionEvent* outEvent = nullptr;
    ErrCode result = ERR_OK;

    if (pointerEvent != nullptr) {
        pointerEvent_ = pointerEvent;
    }
    deferred = false;
    status = ERR_WOULD_BLOCK;

    if (frameTime_ <= 0) {
        if (0 != frameTime) {
            frameTime_ = frameTime;
        } else if (nullptr != pointerEvent) {
            frameTime_ = GetSysClockTime();
        } else {
            frameTime_ = 0;
        }
    }

    // Check that event can be consumed and initialize motion event.
    if (nullptr != pointerEvent) {
        pointerAction = pointerEvent->GetPointerAction();
        MMI_HILOGD("pointerAction:%{public}d %{public}" PRId64 "%{public}" PRId64, pointerAction, pointerEvent->GetActionTime(), frameTime);
        switch (pointerAction) {
            case PointerEvent::POINTER_ACTION_DOWN:
            case PointerEvent::POINTER_ACTION_MOVE:
            case PointerEvent::POINTER_ACTION_UP:
            case PointerEvent::POINTER_ACTION_CANCEL:
                break;
            default:
                status = ERR_WOULD_BLOCK;
                return pointerEvent;
        }
        inputEvent_.reset();
        inputEvent_.initializeFrom(pointerEvent);

        for (auto &it : inputEvent_.pointers) {
            MMI_HILOGD("Input event: %{public}d %{public}d %{public}" PRId64 " %{public}" PRId64, it.second.coordX, it.second.coordY, inputEvent_.actionTime, frameTime_);
        }
    } else {
        inputEvent_.reset();
    }

    do {
        // All events are dispathed so consume batches
        if (PointerEvent::POINTER_ACTION_UNKNOWN == inputEvent_.pointerAction) {
            if (msgDeferred_ == true) {
                msgDeferred_ = false;
                deferred = false;
                outEvent = &deferredEvent_;
                result = ERR_OK;
                break;
            }
            result = consumeBatch(frameTime_, &outEvent);
            frameTime_ = 0;
            if ((ERR_OK == result) && (NULL != outEvent)) {
                status = result;
                break;
            } else {
                status = result;
                return nullptr;
            }
        }

        // Add event into batch
        ssize_t batchIndex = findBatch(inputEvent_.deviceId, inputEvent_.sourceType);
        if (batchIndex >= 0) {
            Batch& batch = batches_.at(batchIndex);
            if (canAddSample(batch, inputEvent_)) {
                batch.samples.push_back(inputEvent_);
                MMI_HILOGD("Event added to batch: %{public}d %{public}d %{public}d",
                           inputEvent_.deviceId, inputEvent_.sourceType, inputEvent_.pointerAction);
                break;
            } else {
                MMI_HILOGD("Deferred event: %{public}d %{public}d %{public}d", inputEvent_.deviceId, inputEvent_.sourceType, inputEvent_.pointerAction);
                deferredEvent_.initializeFrom(inputEvent_);
                msgDeferred_ = true;
                deferred = true;
                result = consumeSamples(batch, batch.samples.size(), &outEvent);
                batches_.erase(batches_.begin() + batchIndex);
                updateTouchState(deferredEvent_);
                break;
            }
        }

        // Start a new batch
        if (PointerEvent::POINTER_ACTION_MOVE == inputEvent_.pointerAction) {
            Batch batch;
            batch.samples.push_back(inputEvent_);
            batches_.push_back(std::move(batch));
            break;
        }

        // Update touch state object
        MMI_HILOGW("updateTouchState");
        updateTouchState(inputEvent_);
        outEvent = &inputEvent_;
    } while (0);

    if ((ERR_OK == result) && (NULL != outEvent)) {
        // Update pointer event
        updatePointerEvent(outEvent);
        return pointerEvent_;
    }

    return nullptr;
}

std::shared_ptr<PointerEvent> EventResample::getPointerEvent()
{
    return pointerEvent_;
}

void EventResample::updatePointerEvent(MotionEvent* outEvent)
{
    pointerEvent_->SetActionTime(outEvent->actionTime);
    pointerEvent_->SetPointerAction(outEvent->pointerAction);
    for (auto &it : outEvent->pointers) {
        MMI_HILOGD("Output event: %{public}d %{public}d %{public}" PRId64, it.second.coordX, it.second.coordY, outEvent->actionTime);
        PointerEvent::PointerItem item;
        if (pointerEvent_->GetPointerItem(it.first, item)) {
            item.SetDisplayX(it.second.coordX);
            item.SetDisplayY(it.second.coordY);
        }
    }
}

ErrCode EventResample::consumeBatch(int64_t frameTime, MotionEvent** outEvent)
{
    int32_t result;
    for (size_t i = batches_.size(); i > 0; ) {
        i--;
        Batch& batch = batches_.at(i);
        if (frameTime < 0) {
            result = consumeSamples(batch, batch.samples.size(), outEvent);
            batches_.erase(batches_.begin() + i);
            return result;
        }

        int64_t sampleTime = frameTime;
        if (resampleTouch_) {
            sampleTime -= RESAMPLE_LATENCY;
        }
        ssize_t split = findSampleNoLaterThan(batch, sampleTime);
        if (split < 0) {
            continue;
        }

        result = consumeSamples(batch, split + 1, outEvent);
        const MotionEvent* next;
        if (batch.samples.empty()) {
            batches_.erase(batches_.begin() + i);
            next = NULL;
        } else {
            next = &batch.samples.at(0);
        }
        if (!result && resampleTouch_) {
           resampleTouchState(sampleTime, static_cast<MotionEvent*>(*outEvent), next);
        }
        return result;
    }

    return ERR_WOULD_BLOCK;
}

ErrCode EventResample::consumeSamples(Batch& batch, size_t count, MotionEvent** outEvent)
{
    outputEvent_.reset();

    for (size_t i = 0; i < count; i++) {
        MotionEvent& event = batch.samples.at(i);
        updateTouchState(event);
        if (i > 0) {
            addSample(&outputEvent_, &event);
        } else {
            outputEvent_.initializeFrom(event);
        }
    }
    batch.samples.erase(batch.samples.begin(), batch.samples.begin() + count);

    *outEvent = &outputEvent_;

    return ERR_OK;
}

void EventResample::addSample(MotionEvent* outEvent, const MotionEvent* event)
{
    outEvent->actionTime = event->actionTime;
    for (auto &it : event->pointers) {
        outEvent->pointers[it.first] = it.second;
    }
}

void EventResample::updateTouchState(MotionEvent &event)
{
    int32_t deviceId = event.deviceId;
    int32_t source = event.sourceType;

    switch (event.pointerAction) {
        case PointerEvent::POINTER_ACTION_DOWN: {
            ssize_t idx = findTouchState(deviceId, source);
            if (idx < 0) {
                TouchState newState;
                touchStates_.push_back(newState);
                idx = touchStates_.size() - 1;
            }
            TouchState& touchState = touchStates_.at(idx);
            touchState.initialize(deviceId, source);
            touchState.addHistory(event);
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            ssize_t idx = findTouchState(deviceId, source);
            if (idx >= 0) {
                TouchState& touchState = touchStates_.at(idx);
                touchState.addHistory(event);
                rewriteMessage(touchState, event);
            }
            break;
        }
        case PointerEvent::POINTER_ACTION_UP:
        case PointerEvent::POINTER_ACTION_CANCEL: {
            ssize_t idx = findTouchState(deviceId, source);
            if (idx >= 0) {
                TouchState& touchState = touchStates_.at(idx);
                rewriteMessage(touchState, event);
                touchStates_.erase(touchStates_.begin() + idx);
            }
            break;
        }
        default: {
            break;
        }
    }
}

void EventResample::resampleTouchState(int64_t sampleTime, MotionEvent* event, const MotionEvent* next)
{
    if (!resampleTouch_ || (PointerEvent::SOURCE_TYPE_TOUCHSCREEN != event->sourceType) || (PointerEvent::POINTER_ACTION_MOVE != event->pointerAction)) {
        return;
    }

    ssize_t idx = findTouchState(event->deviceId, event->sourceType);
    if (idx < 0) {
        return;
    }

    TouchState& touchState = touchStates_.at(idx);
    if (touchState.historySize < 1) {
        return;
    }

    // Ensure that the current sample has all of the pointers that need to be reported.
    const History* current = touchState.getHistory(0);
    for (auto &it : event->pointers) {
        if (!current->hasPointerId(it.first)) {
            return;
        }
    }

    // Find the data to use for resampling.
    const History* other;
    History future;
    float alpha;
    if (next) {
        // Interpolate between current sample and future sample.
        // So current->actionTime <= sampleTime <= future.actionTime.
        future.initializeFrom(*next);
        other = &future;
        int64_t delta = future.actionTime - current->actionTime;
        if (delta < RESAMPLE_MIN_DELTA) {
            return;
        }
        alpha = static_cast<float>(sampleTime - current->actionTime) / delta;
    } else if (touchState.historySize >= 2) {
        // Extrapolate future sample using current sample and past sample.
        // So other->actionTime <= current->actionTime <= sampleTime.
        other = touchState.getHistory(1);
        int64_t delta = current->actionTime - other->actionTime;
        if (delta < RESAMPLE_MIN_DELTA) {
            return;
        } else if (delta > RESAMPLE_MAX_DELTA) {
            return;
        }
        int64_t maxPredict = current->actionTime + std::min(delta / 2, RESAMPLE_MAX_PREDICTION);
        if (sampleTime > maxPredict) {
            sampleTime = maxPredict;
        }
        alpha = static_cast<float>(current->actionTime - sampleTime) / delta;
    } else {
        return;
    }

    // Resample touch coordinates.
    History oldLastResample;
    oldLastResample.initializeFrom(touchState.lastResample);
    touchState.lastResample.actionTime = sampleTime;

    for (auto &it : event->pointers) {
        uint32_t id = it.first;
        if (oldLastResample.hasPointerId(id) && touchState.recentCoordinatesAreIdentical(id)) {
            auto lastItem = touchState.lastResample.pointers.find(id);
            if (lastItem != touchState.lastResample.pointers.end()) {
                auto oldLastItem = oldLastResample.pointers.find(id);
                lastItem->second.copyFrom(oldLastItem->second);
            }
            continue;
        }

        Pointer& resampledCoords = touchState.lastResample.pointers.find(id)->second;
        const Pointer& currentCoords = current->getPointerById(id);
        resampledCoords.copyFrom(currentCoords);
        auto item = event->pointers.find(id);
        if (item == event->pointers.end()) {
            return;
        }
        if (other->hasPointerId(id) && shouldResampleTool(item->second.toolType)) {
            const Pointer& otherCoords = other->getPointerById(id);
            resampledCoords.coordX = calcCoord(currentCoords.coordX, otherCoords.coordX, alpha);
            resampledCoords.coordY = calcCoord(currentCoords.coordY, otherCoords.coordY, alpha);
        } else {
        }
        item->second.copyFrom(resampledCoords);
    }
}

ssize_t EventResample::findBatch(int32_t deviceId, int32_t source) const
{
    ssize_t idx = 0;
    for (auto it = batches_.begin(); it < batches_.end(); ++it, ++idx) {
        const MotionEvent& head = it->samples.at(0);
        if ((head.deviceId == deviceId) && (head.sourceType == source)) {
            return idx;
        }
    }
    return -1;
}

ssize_t EventResample::findTouchState(int32_t deviceId, int32_t source) const
{
    ssize_t idx = 0;
    for (auto it = touchStates_.begin(); it < touchStates_.end(); ++it, ++idx) {
        if ((it->deviceId == deviceId) && (it->source == source)) {
            return idx;
        }
    }
    return -1;
}

bool EventResample::canAddSample(const Batch &batch, MotionEvent &event)
{
    const MotionEvent& head = batch.samples.at(0);
    uint32_t pointerCount = event.pointerCount;
    int32_t pointerAction = event.pointerAction;
    if ((head.pointerCount != pointerCount) || (head.pointerAction != pointerAction)) {
        return false;
    }

    return true;
}

void EventResample::rewriteMessage(TouchState& state, MotionEvent &event)
{
    for (auto &it : event.pointers) {
        uint32_t id = it.first;
        if (state.lastResample.hasPointerId(id)) {
            if ((event.actionTime < state.lastResample.actionTime) || state.recentCoordinatesAreIdentical(id)) {
                Pointer& msgCoords = it.second;
                const Pointer& resampleCoords = state.lastResample.getPointerById(id);
                msgCoords.copyFrom(resampleCoords);
            } else {
                state.lastResample.pointers.erase(id);
            }
        }
    }
}

ssize_t EventResample::findSampleNoLaterThan(const Batch& batch, int64_t time)
{
    size_t numSamples = batch.samples.size();
    size_t idx = 0;
    while ((idx < numSamples) && (batch.samples.at(idx).actionTime <= time)) {
        idx += 1;
    }
    return ssize_t(idx) - 1;
}

bool EventResample::shouldResampleTool(int32_t toolType)
{
    switch (toolType) {
        case PointerEvent::TOOL_TYPE_FINGER:
        case PointerEvent::TOOL_TYPE_PEN:
            return true;
        default:
            return false;
    }
}

} // namespace MMI
} // namespace OHOS
