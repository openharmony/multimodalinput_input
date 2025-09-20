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

#ifndef INPUT_ANI_MONITOR_CONSUMER_H
#define INPUT_ANI_MONITOR_CONSUMER_H

#include <functional>
#include <memory>
#include <queue>
#include <uv.h>

#include "window_info.h"

#include "axis_event.h"
#include "ani_input_monitor_common.h"
#include "i_input_event_consumer.h"
#include "key_event.h"
#include "pointer_event.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
enum class MONITORFUNTYPE: int32_t {
    ON_TOUCH,
    ON_TOUCH_BOOL,
    ON_MOUSE,
    ON_MOUSE_RECT,
    ON_PINCH,
    ON_PINCH_FINGERS,
    ON_ROTATE_FINGERS,
    ON_THREEFINGERSWIPE,
    ON_FOURFINGERSWIPE,
    ON_THREEFINGERSTAP,
    ON_FINGERPRINT,
    ON_SWIPEINWARD,
    ON_TOUCHSCREENSWIPE_FINGERS,
    ON_TOUCHSCREENPINCH_FINGERS,
    ON_KEYPRESSED_KEYS,

    OFF_TOUCH,
    OFF_MOUSE,
    OFF_PINCH,
    OFF_PINCH_FINGERS,
    OFF_ROTATE_FINGERS,
    OFF_THREEFINGERSWIPE,
    OFF_FOURFINGERSWIPE,
    OFF_THREEFINGERSTAP,
    OFF_FINGERPRINT,
    OFF_SWIPEINWARD,
    OFF_TOUCHSCREENSWIPE_FINGERS,
    OFF_TOUCHSCREENPINCH_FINGERS,
    OFF_KEYPRESSED_KEYS
};

using ConsumerParmType = std::variant<int32_t, std::vector<Rect>, std::vector<int32_t>>;
class AniInputMonitorConsumer : public IInputEventConsumer,
    public std::enable_shared_from_this<AniInputMonitorConsumer> {
public:
    AniInputMonitorConsumer(MONITORFUNTYPE funType, int32_t fingers, std::vector<Rect> hotRectArea,
        std::vector<int32_t> keys, std::shared_ptr<CallbackObject> &aniCallback);
    ~AniInputMonitorConsumer() override = default;
    int32_t GetId() const;
    int32_t GetFingers() const;
    std::string GetTypeName() const;
    MONITORFUNTYPE GetFunType() const;
    bool CheckOffFuncParam(MONITORFUNTYPE funType, int32_t fingers = 0) const;
    std::shared_ptr<CallbackObject> GetCallback() const
    {
        return aniCallback_;
    }
    bool IsOnFunc() const;
    int32_t Start();
    void Stop();
    static std::shared_ptr<AniInputMonitorConsumer> CreateAniInputMonitorConsumer(MONITORFUNTYPE funType,
        const ConsumerParmType &param, callbackType &&cb, uintptr_t opq);
    static bool IsOnFunc(MONITORFUNTYPE funType)
    {
        if (funType >= MONITORFUNTYPE::ON_TOUCH && funType <= MONITORFUNTYPE::ON_KEYPRESSED_KEYS) {
            return true;
        }
        return false;
    }

    static bool IsOffFunc(MONITORFUNTYPE funType)
    {
        if (funType >= MONITORFUNTYPE::OFF_TOUCH && funType <= MONITORFUNTYPE::OFF_KEYPRESSED_KEYS) {
            return true;
        }
        return false;
    }

protected:
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override;
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override;
    static void AniWorkCallback(uv_work_t *work, int32_t status);

    bool PrepareData(std::shared_ptr<PointerEvent> pointerEvent) const;
    void OnPointerEventInEvThread();
    void OnAniKeyEvent(std::shared_ptr<KeyEvent> keyEvent) const;
    bool IsBeginAndEnd(std::shared_ptr<PointerEvent> pointerEvent) const;
    void SetConsumeState(std::shared_ptr<PointerEvent> pointerEvent) const;
    bool IsPinch(std::shared_ptr<PointerEvent> pointerEvent, const int32_t fingers) const;
    bool IsGestureEvent(std::shared_ptr<PointerEvent> pointerEvent) const;
    bool IsRotate(std::shared_ptr<PointerEvent> pointerEvent) const;
    bool IsThreeFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent) const;
    bool IsFourFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent) const;
    bool IsThreeFingersTap(std::shared_ptr<PointerEvent> pointerEvent) const;
    bool IsJoystick(std::shared_ptr<PointerEvent> pointerEvent) const;
    bool IsSwipeInward(std::shared_ptr<PointerEvent> pointerEvent) const;
    bool IsFingerprint(std::shared_ptr<PointerEvent> pointerEvent) const;
    bool IsLocaledWithinRect(std::shared_ptr<PointerEvent> pointerEvent, std::vector<Rect> hotRectArea) const;

    void CheckConsumed(bool retValue, std::shared_ptr<PointerEvent> pointerEvent);
    void MarkConsumed(int32_t eventId);

private:
    void OnPerPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void OnTouchCallback(std::shared_ptr<PointerEvent> pointerEvent);
    void OnTouchNeedResultCallback(std::shared_ptr<PointerEvent> pointerEvent, bool &retValue);
    void OnMouseCallback(std::shared_ptr<PointerEvent> pointerEvent, bool retRectArea);
    void OnPinchCallback(std::shared_ptr<PointerEvent> pointerEvent);
    void OnRotateCallback(std::shared_ptr<PointerEvent> pointerEvent);
    void OnThreeFingersSwipeCallback(std::shared_ptr<PointerEvent> pointerEvent);
    void OnFourFingersSwipeCallback(std::shared_ptr<PointerEvent> pointerEvent);
    void OnThreeFingersTapCallback(std::shared_ptr<PointerEvent> pointerEvent);
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    void OnFingerprintCallback(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
    void OnSwipeInwardCallback(std::shared_ptr<PointerEvent> pointerEvent);
    void OnTouchScreenPinchCallback(std::shared_ptr<PointerEvent> pointerEvent);
#ifdef OHOS_BUILD_ENABLE_X_KEY
    void OnXkeyCallback(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_X_KEY
    MONITORFUNTYPE funType_;
    int32_t fingers_ { 0 };
    std::vector<int32_t> keys_;
    std::vector<Rect> hotRectArea_;
    std::shared_ptr<CallbackObject> aniCallback_ { nullptr };

    int32_t monitorId_ { -1 };
    [[ maybe_unused ]] bool isMonitoring_ { false };
    mutable bool consumed_ { false };
    mutable std::mutex mutex_;
    mutable int32_t flowCtrl_ { 0 };

    mutable std::queue<std::shared_ptr<PointerEvent>> evQueue_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_ANI_MONITOR_CONSUMER_H

