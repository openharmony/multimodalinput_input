/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TOUCH_GESTURE_ADAPTER_H
#define TOUCH_GESTURE_ADAPTER_H

#include <fstream>
#include <memory>

#include "cJSON.h"

#include "input_handler_type.h"
#include "touch_gesture_detector.h"

namespace OHOS {
namespace MMI {
class TouchGestureParameter {
public:
    static const TouchGestureParameter& Load();
    static bool IsInteger(const char *target);

    bool DoesSupportGesture(TouchGestureType gestureType, int32_t nFingers) const;
    float GetMaxFingerSpacing() const;
    int64_t GetMaxDownInterval() const;
    float GetFingerMovementThreshold() const;

    int32_t GetMaxFingerCountForPinch() const;
    int32_t GetMinFingerCountForPinch() const;
    int32_t GetFingerCountOffsetForPinch() const;
    int32_t GetContinuousPinchesForNotification() const;
    float GetMinGravityOffsetForPinch() const;

    int32_t GetMaxFingerCountForSwipe() const;
    int32_t GetMinFingerCountForSwipe() const;
    int32_t GetMinKeepTimeForSwipe() const;

private:
    void LoadTouchGestureParameter();
    bool LoadTouchGestureParameter(const char *cfgPath);
    bool ReadTouchGestureParameter(std::ifstream &ifs);
    bool ReadTouchGestureParameter(cJSON *jsonProductCfg);
    bool ReadMaxFingerSpacing(cJSON *jsonTouchGesture);
    bool ReadMaxDownInterval(cJSON *jsonTouchGesture);
    bool ReadFingerMovementThreshold(cJSON *jsonTouchGesture);
    bool ReadFingerCountOffsetForPinch(cJSON *jsonTouchGesture);
    bool ReadContinuousPinchesForNotification(cJSON *jsonTouchGesture);
    bool ReadMinGravityOffsetForPinch(cJSON *jsonTouchGesture);
    bool ReadMinKeepTimeForSwipe(cJSON *jsonTouchGesture);

    int32_t maxFingerCountForPinch_ { 5 };
    int32_t minFingerCountForPinch_ { 4 };
    int32_t maxFingerCountForSwipe_ { 5 };
    int32_t minFingerCountForSwipe_ { 3 };
    int32_t fingerCountOffsetForPinch_ { 1 };
    int32_t continuousPinchesForNotification_ { 2 };
    int32_t minKeepTimeForSwipe_ { 15 }; // ms
    int64_t maxDownInterval_ { 100000 }; // us
    float maxFingerSpacing_ { 2000.0F }; // vp
    float fingerMovementThreshold_ { 3.0F }; // vp
    float minGravityOffsetForPinch_ { 0.5F }; // vp
};

class TouchGestureAdapter final :
    public TouchGestureDetector::GestureListener,
    public std::enable_shared_from_this<TouchGestureAdapter> {
public:
    static std::shared_ptr<IDelegateInterface> GetDelegateInterface(IInputServiceContext *env);
    static IUdsServer* GetUDSServer(IInputServiceContext *env);
    static std::shared_ptr<IInputEventHandler> GetEventNormalizeHandler(IInputServiceContext *env);
    static std::shared_ptr<IInputEventHandler> GetMonitorHandler(IInputServiceContext *env);
    static std::shared_ptr<ITimerManager> GetTimerManager(IInputServiceContext *env);
    static std::shared_ptr<IInputWindowsManager> GetInputWindowsManager(IInputServiceContext *env);

    TouchGestureAdapter(IInputServiceContext *env, TouchGestureType type, std::shared_ptr<TouchGestureAdapter> next);
    static std::shared_ptr<TouchGestureAdapter> GetGestureFactory(IInputServiceContext *env);
    void process(std::shared_ptr<PointerEvent> event);
    void SetGestureCondition(bool flag, TouchGestureType type, int32_t fingers);
    void HandleGestureWindowEmerged(int32_t windowId, std::shared_ptr<PointerEvent> lastTouchEvent);

private:
    enum class GestureState {
        IDLE,
        SWIPE,
        PINCH,
    };

    inline bool ShouldDeliverToNext() const
    {
        return shouldDeliverToNext_;
    }
    void Init();
    void LogTouchEvent(std::shared_ptr<PointerEvent> event) const;
    void OnTouchEvent(std::shared_ptr<PointerEvent> event);
    void OnSwipeGesture(std::shared_ptr<PointerEvent> event);
    void OnPinchGesture(std::shared_ptr<PointerEvent> event);
    bool OnGestureEvent(std::shared_ptr<PointerEvent> event, GestureMode mode) override;
    void OnGestureTrend(std::shared_ptr<PointerEvent> event) override;

private:
    IInputServiceContext *env_ { nullptr };
    bool gestureStarted_ { false };
    bool shouldDeliverToNext_ { true };
    TouchGestureType gestureType_ { TOUCH_GESTURE_TYPE_NONE };
    inline static GestureState state_ { GestureState::IDLE };
    std::shared_ptr<TouchGestureDetector> gestureDetector_ { nullptr };
    std::shared_ptr<TouchGestureAdapter> nextAdapter_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // TOUCH_GESTURE_ADAPTER_H