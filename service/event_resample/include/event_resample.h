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

#include <vector>
#include <map>
#include <list>

#include "proto.h"
#include "singleton.h"
#include "nocopyable.h"
#include "error_multimodal.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class EventResample final {
    DECLARE_DELAYED_SINGLETON(EventResample);

public:
    DISALLOW_COPY_AND_MOVE(EventResample);
    std::shared_ptr<PointerEvent> onEventConsume(std::shared_ptr<PointerEvent> pointerEvent, int64_t frameTime, bool &deferred, ErrCode &status);
    std::shared_ptr<PointerEvent> getPointerEvent();

private:

    struct Pointer {
        int32_t coordX;
        int32_t coordY;
        int32_t toolType;
        int32_t id;

        void copyFrom(const Pointer& other) {
            coordX = other.coordX;
            coordY = other.coordY;
            toolType = other.toolType;
            id = other.id;
        }

        void reset() {
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

        void reset() {
            pointers.clear();
            actionTime = 0;
            pointerCount = 0;
            sourceType = PointerEvent::SOURCE_TYPE_UNKNOWN;
            pointerAction = PointerEvent::POINTER_ACTION_UNKNOWN;
            deviceId = 0;
        }

        void initializeFrom(MotionEvent& other) {
            for (auto &it : other.pointers) {
                pointers[it.first] = it.second;
            }
            actionTime = other.actionTime;
            pointerCount = other.pointerCount;
            deviceId = other.deviceId;
            sourceType = other.sourceType;
            pointerAction = other.pointerAction;
        }

        void initializeFrom(std::shared_ptr<PointerEvent> event) {
            actionTime = event->GetActionTime();
            deviceId = event->GetDeviceId();
            sourceType = event->GetSourceType();
            pointerAction = event->GetPointerAction();

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

        void initializeFrom(const MotionEvent &event) {
            actionTime = event.actionTime;
            for (auto &it : event.pointers) {
                pointers[it.first] = it.second;
            }
        }

        void initializeFrom(const History &other) {
            actionTime = other.actionTime;
            for (auto &it : other.pointers) {
                pointers[it.first] = it.second;
            }
        }

        const Pointer& getPointerById(uint32_t id) const {
            auto item = pointers.find(id);
            return item->second;
        }

        bool hasPointerId(uint32_t id) const {
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
        History history[2];
        History lastResample;

        void initialize(int32_t deviceId, int32_t source) {
            this->deviceId = deviceId;
            this->source = source;
            historyCurrent = 0;
            historySize = 0;
            lastResample.actionTime = 0;
        }

        void addHistory(const MotionEvent &event) {
            historyCurrent ^= 1;
            if (historySize < 2) {
                historySize += 1;
            }
            history[historyCurrent].initializeFrom(event);
        }

        const History* getHistory(size_t idx) const {
            return &history[(historyCurrent + idx) & 1];
        }

        bool recentCoordinatesAreIdentical(uint32_t id) const {
            // Return true if the two most recently received "raw" coordinates are identical
            if (historySize < 2) {
                return false;
            }
            if (!getHistory(0)->hasPointerId(id) || !getHistory(1)->hasPointerId(id)) {
                return false;
            }
            float currentX = getHistory(0)->getPointerById(id).coordX;
            float currentY = getHistory(0)->getPointerById(id).coordY;
            float previousX = getHistory(1)->getPointerById(id).coordX;
            float previousY = getHistory(1)->getPointerById(id).coordY;
            if (currentX == previousX && currentY == previousY) {
                return true;
            }
            return false;
        }
    };
    std::vector<TouchState> touchStates_;

    MotionEvent inputEvent_;
    MotionEvent outputEvent_;
    MotionEvent deferredEvent_;
    int64_t frameTime_ {-1};
    bool msgDeferred_ {false};
    bool resampleTouch_ {true};
    std::shared_ptr<PointerEvent> pointerEvent_ {nullptr};

    void updatePointerEvent(MotionEvent* outEvent);
    ErrCode consumeBatch(int64_t frameTime, MotionEvent** outEvent);
    ErrCode consumeSamples(Batch& batch, size_t count, MotionEvent** outEvent);
    void addSample(MotionEvent* outEvent, const MotionEvent* event);
    void updateTouchState(MotionEvent &event);
    void resampleTouchState(int64_t sampleTime, MotionEvent* event, const MotionEvent* next);
    ssize_t findBatch(int32_t deviceId, int32_t source) const;
    ssize_t findTouchState(int32_t deviceId, int32_t source) const;
    bool canAddSample(const Batch &batch, MotionEvent &event);
    void rewriteMessage(TouchState& state, MotionEvent &event);
    ssize_t findSampleNoLaterThan(const Batch& batch, int64_t time);
    bool shouldResampleTool(int32_t toolType);

};

inline static float calcCoord(float a, float b, float alpha) {
    return a + alpha * (b - a);
}

#define EventResampleHdr ::OHOS::DelayedSingleton<EventResample>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // EVENT_RESAMPLE_H
