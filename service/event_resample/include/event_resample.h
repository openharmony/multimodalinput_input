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

#ifndef EVENT_RESAMPLE_H
#define EVENT_RESAMPLE_H

#include <map>

#include "singleton.h"
#include "error_multimodal.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class EventResample final {
    DECLARE_DELAYED_SINGLETON(EventResample);

public:
    DISALLOW_COPY_AND_MOVE(EventResample);
    std::shared_ptr<PointerEvent> OnEventConsume(std::shared_ptr<PointerEvent> pointerEvent,
                                                 int64_t frameTime, ErrCode &status);
    std::shared_ptr<PointerEvent> GetPointerEvent();

    void PrintfDeviceName();
    
    // Microseconds per milliseconds.
    static constexpr int64_t US_PER_MS = 1000;

    // Latency added during resampling. A few milliseconds doesn't hurt much but
    // reduces the impact of mispredicted touch positions.
    static constexpr int64_t RESAMPLE_LATENCY = 5 * US_PER_MS;

    // Minimum time difference between consecutive samples before attempting to resample.
    static constexpr int64_t RESAMPLE_MIN_DELTA = 2 * US_PER_MS;

    // Maximum time difference between consecutive samples before attempting to resample
    // by extrapolation.
    static constexpr int64_t RESAMPLE_MAX_DELTA = 20 * US_PER_MS;

    // Maximum time to predict forward from the last known state, to avoid predicting too
    // far into the future. This time is further bounded by 50% of the last time delta.
    static constexpr int64_t RESAMPLE_MAX_PREDICTION = 4 * US_PER_MS;

    // Maximum history size to store samples
    static constexpr size_t HISTORY_SIZE_MAX = 2;

private:

    struct Pointer {
        int32_t coordX;
        int32_t coordY;
        int32_t toolType;
        int32_t id;

        void CopyFrom(const Pointer& other)
        {
            coordX = other.coordX;
            coordY = other.coordY;
            toolType = other.toolType;
            id = other.id;
        }

        void Reset()
        {
            coordX = 0;
            coordY = 0;
            toolType = 0;
            id = 0;
        }
    };

    struct MotionEvent {
        std::map<uint32_t, Pointer> pointers;
        int64_t actionTime { 0 };
        uint32_t pointerCount { 0 };
        int32_t sourceType { PointerEvent::SOURCE_TYPE_UNKNOWN };
        int32_t pointerAction { PointerEvent::POINTER_ACTION_UNKNOWN };
        int32_t deviceId { 0 };
        int32_t eventId { 0 };

        void Reset()
        {
            pointers.clear();
            actionTime = 0;
            pointerCount = 0;
            sourceType = PointerEvent::SOURCE_TYPE_UNKNOWN;
            pointerAction = PointerEvent::POINTER_ACTION_UNKNOWN;
            deviceId = 0;
            eventId = 0;
        }

        void InitializeFrom(MotionEvent& other)
        {
            for (auto &it : other.pointers) {
                pointers[it.first] = it.second;
            }
            actionTime = other.actionTime;
            pointerCount = other.pointerCount;
            deviceId = other.deviceId;
            sourceType = other.sourceType;
            pointerAction = other.pointerAction;
            eventId = other.eventId;
        }

        void InitializeFrom(std::shared_ptr<PointerEvent> event)
        {
            actionTime = event->GetActionTime();
            deviceId = event->GetDeviceId();
            sourceType = event->GetSourceType();
            pointerAction = event->GetPointerAction();
            eventId = event->GetId();

            std::vector<int32_t> pointerIds = event->GetPointerIds();
            pointerCount = 0;
            for (auto &it : pointerIds) {
                PointerEvent::PointerItem item;
                if (event->GetPointerItem(it, item)) {
                    Pointer pointer;
                    pointer.coordX = item.GetDisplayX();
                    pointer.coordY = item.GetDisplayY();
                    pointer.toolType = item.GetToolType();
                    pointer.id = item.GetPointerId();
                    pointers[pointer.id] = pointer;
                    pointerCount++;
                }
            }
        }
    };

    struct Batch {
        std::vector<MotionEvent> samples;
    };
    std::vector<Batch> batches_;

    struct History {
        std::map<uint32_t, Pointer> pointers;
        int64_t actionTime { 0 };

        void InitializeFrom(const MotionEvent &event)
        {
            actionTime = event.actionTime;
            for (auto &it : event.pointers) {
                pointers[it.first] = it.second;
            }
        }

        void InitializeFrom(const History &other)
        {
            actionTime = other.actionTime;
            for (auto &it : other.pointers) {
                pointers[it.first] = it.second;
            }
        }

        const Pointer& GetPointerById(uint32_t id) const
        {
            auto item = pointers.find(id);
            return item->second;
        }

        bool HasPointerId(uint32_t id) const
        {
            auto item = pointers.find(id);
            if (item != pointers.end()) {
                return true;
            } else {
                return false;
            }
        }
    };

    struct TouchState {
        int32_t deviceId;
        int32_t source;
        size_t historyCurrent;
        size_t historySize;
        History history[HISTORY_SIZE_MAX];
        History lastResample;

        void Initialize(int32_t deviceId, int32_t source)
        {
            this->deviceId = deviceId;
            this->source = source;
            historyCurrent = 0;
            historySize = 0;
            lastResample.actionTime = 0;
        }

        void AddHistory(const MotionEvent &event)
        {
            historyCurrent ^= 1;
            if (historySize < HISTORY_SIZE_MAX) {
                historySize += 1;
            }
            history[historyCurrent].InitializeFrom(event);
        }

        const History* GetHistory(size_t idx) const
        {
            return &history[(historyCurrent + idx) & 1];
        }

        bool RecentCoordinatesAreIdentical(uint32_t id) const
        {
            // Return true if the two most recently received "raw" coordinates are identical
            if (historySize < HISTORY_SIZE_MAX) {
                return false;
            }
            if (!GetHistory(0)->HasPointerId(id) || !GetHistory(1)->HasPointerId(id)) {
                return false;
            }
            float currentX = GetHistory(0)->GetPointerById(id).coordX;
            float currentY = GetHistory(0)->GetPointerById(id).coordY;
            float previousX = GetHistory(1)->GetPointerById(id).coordX;
            float previousY = GetHistory(1)->GetPointerById(id).coordY;
            if (currentX == previousX && currentY == previousY) {
                return true;
            }
            return false;
        }
    };
    std::vector<TouchState> touchStates_;

    MotionEvent inputEvent_;
    MotionEvent outputEvent_;
    int64_t frameTime_ {-1};
    bool resampleTouch_ {true};
    std::shared_ptr<PointerEvent> pointerEvent_ {nullptr};

    void EventDump(const char *msg, MotionEvent &event);
    ErrCode InitializeInputEvent(std::shared_ptr<PointerEvent> pointerEvent, int64_t frameTime);
    bool UpdateBatch(MotionEvent** outEvent, ErrCode &result);
    void UpdatePointerEvent(MotionEvent* outEvent);
    ErrCode ConsumeBatch(int64_t frameTime, MotionEvent** outEvent);
    ErrCode ConsumeSamples(Batch& batch, size_t count, MotionEvent** outEvent);
    void AddSample(MotionEvent* outEvent, const MotionEvent* event);
    void UpdateTouchState(MotionEvent &event);
    void ResampleTouchState(int64_t sampleTime, MotionEvent* event, const MotionEvent* next);
    void ResampleCoordinates(int64_t sampleTime, MotionEvent* event, TouchState &touchState,
                             const History* current, const History* other, float alpha);
    ssize_t FindBatch(int32_t deviceId, int32_t source) const;
    ssize_t FindTouchState(int32_t deviceId, int32_t source) const;
    bool CanAddSample(const Batch &batch, MotionEvent &event);
    void RewriteMessage(TouchState& state, MotionEvent &event);
    ssize_t FindSampleNoLaterThan(const Batch& batch, int64_t time);
    bool ShouldResampleTool(int32_t toolType);
    std::pair<int32_t, int32_t> TransformSampleWindowXY(std::shared_ptr<PointerEvent> pointerEvent,
        PointerEvent::PointerItem &item, int32_t logicX, int32_t logicY);
};

inline static float CalcCoord(float a, float b, float alpha)
{
    return a + alpha * (b - a);
}

#define EventResampleHdr ::OHOS::DelayedSingleton<EventResample>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // EVENT_RESAMPLE_H
