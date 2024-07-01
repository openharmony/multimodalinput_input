/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef TOUCHPAD_TRANSFORM_PROCESSOR_H
#define TOUCHPAD_TRANSFORM_PROCESSOR_H

#include "singleton.h"
#include "nocopyable.h"
#include "aggregator.h"
#include "timer_manager.h"
#include "transform_processor.h"
#include <map>

namespace OHOS {
namespace MMI {
enum class MulFingersTap : int32_t {
    NO_TAP = 0,
    TRIPLETAP = 3,
    QUADTAP = 4,
    QUINTTAP = 5,
};

class MultiFingersTapHandler final {
    DECLARE_DELAYED_SINGLETON(MultiFingersTapHandler);

public:
    DISALLOW_COPY_AND_MOVE(MultiFingersTapHandler);

    enum class TapTrends : int32_t {
        BEGIN = 0,
        DOWNING = 1,
        UPING = 2,
        NOMULTAP = 3,
    };

    int32_t HandleMulFingersTap(struct libinput_event_touch *event, int32_t type);
    MulFingersTap GetMultiFingersState() const;
    void SetMULTI_FINGERTAP_HDRDefault(bool isAllDefault = true);
    bool ClearPointerItems(std::shared_ptr<PointerEvent> pointer);
    bool IsInvalidMulTapGesture(struct libinput_event_touch *event);
    bool CanAddToPointerMaps(struct libinput_event_touch *event);
    bool CanUnsetPointerItem(struct libinput_event_touch *event);

private:
    int32_t downCnt = 0;
    int32_t upCnt = 0;
    int32_t motionCnt = 0;
    TapTrends tapTrends_ = TapTrends::BEGIN;
    MulFingersTap multiFingersState_ = MulFingersTap::NO_TAP;
    uint64_t lastTime = 0;
    uint64_t beginTime = 0;
    std::map<int32_t, std::pair<float, float>> pointerMaps;
    const uint64_t perTimeThreshold = 150 * 1e3;
    const uint64_t totalTimeThreshold = 500 * 1e3;
    const float distanceThreshold = 0.2F;
};
#define MULTI_FINGERTAP_HDR ::OHOS::DelayedSingleton<MultiFingersTapHandler>::GetInstance()

class TouchPadTransformProcessor final : public TransformProcessor {
public:
    explicit TouchPadTransformProcessor(int32_t deviceId);
    DISALLOW_COPY_AND_MOVE(TouchPadTransformProcessor);
    ~TouchPadTransformProcessor() = default;
    std::shared_ptr<PointerEvent> OnEvent(struct libinput_event *event) override;
    std::shared_ptr<PointerEvent> GetPointerEvent() override;
    static int32_t SetTouchpadThreeFingersTapSwitch(bool switchFlag);
    static int32_t GetTouchpadThreeFingersTapSwitch(bool &switchFlag);
    static int32_t SetTouchpadPinchSwitch(bool switchFlag);
    static void GetTouchpadPinchSwitch(bool &switchFlag);
    static int32_t SetTouchpadSwipeSwitch(bool switchFlag);
    static void GetTouchpadSwipeSwitch(bool &switchFlag);
    static int32_t SetTouchpadRotateSwitch(bool rotateSwitch);
    static void GetTouchpadRotateSwitch(bool &rotateSwitch);
    static int32_t SetTouchpadScrollRows(int32_t rows);
    static int32_t GetTouchpadScrollRows();

private:
    static int32_t PutConfigDataToDatabase(std::string &key, bool value);
    static void GetConfigDataFromDatabase(std::string &key, bool &value);

    int32_t OnEventTouchPadDown(struct libinput_event *event);
    int32_t OnEventTouchPadMotion(struct libinput_event *event);
    int32_t OnEventTouchPadUp(struct libinput_event *event);
    int32_t SetTouchPadSwipeData(struct libinput_event *event, int32_t action);
    int32_t AddItemForEventWhileSetSwipeData(int64_t time, libinput_event_gesture *gesture, int32_t fingerCount);
    int32_t OnEventTouchPadSwipeBegin(struct libinput_event *event);
    int32_t OnEventTouchPadSwipeUpdate(struct libinput_event *event);
    int32_t OnEventTouchPadSwipeEnd(struct libinput_event *event);
    int32_t OnEventTouchPadPinchBegin(struct libinput_event *event);
    int32_t OnEventTouchPadPinchUpdate(struct libinput_event *event);
    int32_t OnEventTouchPadPinchEnd(struct libinput_event *event);
    int32_t SetTouchPadPinchData(struct libinput_event *event, int32_t action);
    void SetTouchPadMultiTapData();
    void SetPinchPointerItem(int64_t time);
    void ProcessTouchPadPinchDataEvent(int32_t fingerCount, int32_t action, double scale);

    int32_t GetTouchPadToolType(struct libinput_event_touch *data, struct libinput_device *device);
    int32_t GetTouchPadToolType(struct libinput_device *device);
    void InitToolType();
private:
    const int32_t deviceId_ { -1 };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    std::vector<std::pair<int32_t, int32_t>> vecToolType_;
    Aggregator aggregator_ {
            [](int32_t intervalMs, int32_t repeatCount, std::function<void()> callback) -> int32_t {
                return TimerMgr->AddTimer(intervalMs, repeatCount, std::move(callback));
            },
            [](int32_t timerId) -> int32_t
            {
                return TimerMgr->ResetTimer(timerId);
            }
    };
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCHPAD_TRANSFORM_PROCESSOR_H