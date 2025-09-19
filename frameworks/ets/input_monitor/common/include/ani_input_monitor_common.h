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

#ifndef ANI_INPUT_TAIHE_INPUT_MONITOR_COMMON_H
#define ANI_INPUT_TAIHE_INPUT_MONITOR_COMMON_H

#include <map>
#include <string>
#include <variant>

#include "ani_common.h"
#include "securec.h"

#include "ohos.multimodalInput.mouseEvent.proj.hpp"
#include "ohos.multimodalInput.gestureEvent.proj.hpp"
#include "ohos.multimodalInput.touchEvent.proj.hpp"
#include "ohos.multimodalInput.shortKey.proj.hpp"
#include "ohos.multimodalInput.keyEvent.proj.hpp"
#include "taihe/runtime.hpp"
#include "taihe/callback.hpp"

#include "key_event.h"
#include "pointer_style.h"
#include "pointer_event.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {

constexpr int32_t AXIS_TYPE_SCROLL_VERTICAL { 0 };
constexpr int32_t AXIS_TYPE_SCROLL_HORIZONTAL { 1 };
constexpr int32_t AXIS_TYPE_PINCH { 2 };

using namespace ohos::multimodalInput::keyCode;
using TaiheAxisValue = ::ohos::multimodalInput::mouseEvent::AxisValue;
using TaiheAxis = ::ohos::multimodalInput::mouseEvent::Axis;
using TaiheInputEvent = ohos::multimodalInput::inputEvent::InputEvent;
using TaiheMouseToolType = ohos::multimodalInput::mouseEvent::ToolType;
using TaiheMouseButton = ::ohos::multimodalInput::mouseEvent::Button;
using TaiheKeyCode = ::ohos::multimodalInput::keyCode::KeyCode;

using TaiheMouseEvent = ohos::multimodalInput::mouseEvent::MouseEvent;
using TaiheTouchEvent = ohos::multimodalInput::touchEvent::TouchEvent;
using TaiheTouchEventArray = taihe::array<TaiheTouchEvent>;
using TaiheTouch = ohos::multimodalInput::touchEvent::Touch;
using TaiheTouchAction =  ohos::multimodalInput::touchEvent::Action;
using TaiheMouseAction =  ohos::multimodalInput::mouseEvent::Action;
using TaiheInputEvent = ohos::multimodalInput::inputEvent::InputEvent;
using TaiheSourceType = ohos::multimodalInput::touchEvent::SourceType;
using TaiheFixedMode = ohos::multimodalInput::touchEvent::FixedMode;
using TaiheToolType = ohos::multimodalInput::touchEvent::ToolType;

using TaiheRotate = ohos::multimodalInput::gestureEvent::Rotate;
using TaiheTouchGestureAction = ohos::multimodalInput::gestureEvent::TouchGestureAction;
using TaiheGestureActionType = ohos::multimodalInput::gestureEvent::ActionType;
using TaiheSwipeInward = ohos::multimodalInput::gestureEvent::SwipeInward;
using TaiheThreeFingersSwipe = ohos::multimodalInput::gestureEvent::ThreeFingersSwipe;
using TaihePinchEvent = ohos::multimodalInput::gestureEvent::Pinch;
using TaiheFourFingersSwipe = ohos::multimodalInput::gestureEvent::FourFingersSwipe;
using TaiheThreeFingersTap = ohos::multimodalInput::gestureEvent::ThreeFingersTap;
using TaiheTouchGestureEvent = ohos::multimodalInput::gestureEvent::TouchGestureEvent;

using TaiheFingerprintAction = ohos::multimodalInput::shortKey::FingerprintAction;
using TaiheFingerprintEvent = ohos::multimodalInput::shortKey::FingerprintEvent;

using TaiheKeyEventAction = ohos::multimodalInput::keyEvent::Action;
using TaiheKeyEvent = ohos::multimodalInput::keyEvent::KeyEvent;
using TaiheKeyEventKey = ohos::multimodalInput::keyEvent::Key;

enum TH_MOUSE_BUTTON {
    JS_MOUSE_BUTTON_LEFT = 0,
    JS_MOUSE_BUTTON_MIDDLE = 1,
    JS_MOUSE_BUTTON_RIGHT = 2,
    JS_MOUSE_BUTTON_SIDE = 3,
    JS_MOUSE_BUTTON_EXTRA = 4,
    JS_MOUSE_BUTTON_FORWARD = 5,
    JS_MOUSE_BUTTON_BACK = 6,
    JS_MOUSE_BUTTON_TASK = 7
};

class TaiheMonitorConverter {
public:
    // touchEvent
    static int32_t TouchEventToTaihe(const PointerEvent &pointerEvent, TaiheTouchEvent &out);
    static int32_t InputEventToTaihe(const InputEvent &inputEvent, TaiheInputEvent &out);
    static int32_t TouchActionToTaihe(int32_t action, TaiheTouchAction &out);
    static int32_t SourceTypeToTaihe(int32_t sourceType, TaiheSourceType &out);
    static int32_t FixedModeToTaihe(PointerEvent::FixedMode fixedMode, TaiheFixedMode &out);
    static int32_t TouchToTaihe(const PointerEvent::PointerItem &item, TaiheTouch &out);

    // gestureEvent
    static int32_t TouchGestureActionToTaihe(int32_t action, TaiheTouchGestureAction &out);
    static int32_t RotateActionToTaihe(int32_t action, TaiheGestureActionType &out);
    static int32_t PinchActionToTaihe(int32_t action, TaiheGestureActionType &out);
    static int32_t SwipeInwardActionToTaihe(int32_t action, TaiheGestureActionType &out);
    static int32_t SwipeActionToTaihe(int32_t action, TaiheGestureActionType &out);
    static int32_t MultiTapActionToTaihe(int32_t action, TaiheGestureActionType &out);

    static int32_t RotateToTaihe(const PointerEvent &pointerEvent, TaiheRotate &out);
    static int32_t PinchToTaihe(const PointerEvent &pointerEvent, TaihePinchEvent &out);
    static int32_t SwipeInwardToTaihe(const PointerEvent &pointerEvent, TaiheSwipeInward &out);
    static int32_t ThreeFingersSwipeToTaihe(const PointerEvent &pointerEvent, TaiheThreeFingersSwipe &out);
    static int32_t FourFingersSwipeToTaihe(const PointerEvent &pointerEvent, TaiheFourFingersSwipe &out);
    // touchscreenSwipe, touchscreenPinch
    static int32_t TouchGestureEventToTaihe(const PointerEvent &pointerEvent, TaiheTouchGestureEvent &out);
    // fingersTap
    static int32_t ThreeFingersTapToTaihe(const PointerEvent &pointerEvent, TaiheThreeFingersTap &out);
    // fingerprint
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    static int32_t FingerprintActionToTaihe(int32_t action, TaiheFingerprintAction &out);
    static int32_t FingerprintEventToTaihe(const PointerEvent &pointerEvent, TaiheFingerprintEvent &out);
#endif
    // keyPressed
    static bool HasKeyCode(const std::vector<int32_t>& pressedKeys, int32_t keyCode);
    static int32_t KeyEventActionToTaihe(int32_t action, TaiheKeyEventAction &out);
    static int32_t TaiheKeyEventToTaihe(const KeyEvent &keyEvent, TaiheKeyEvent &out);
    static int32_t TaiheKeyEventKeyToTaihe(const KeyEvent::KeyItem &keyItem, TaiheKeyEventKey &out);
    static int32_t MouseEventToTaihe(std::shared_ptr<PointerEvent> pointerEvent, TaiheMouseEvent &out);
    static int32_t MouseActionToTaihe(int32_t action, TaiheMouseAction &out);
    static bool ParseRect(ani_env *env, ani_object rect, Rect &result);
    static bool GetIntObject(ani_env* env, const char* propertyName, ani_object object, int32_t& result);
    static bool ParseRects(ani_object aniRects, std::vector<Rect> &rects, int32_t maxNum);
private:
    static int32_t GetMousePointerItem(std::shared_ptr<PointerEvent> pointerEvent, TaiheMouseEvent &mouseEvent);
    static int32_t SetMouseProperty(std::shared_ptr<PointerEvent> pointerEvent,
        const PointerEvent::PointerItem& item, TaiheMouseEvent &mouseEvent);
    static int32_t GetAxesValue(const std::shared_ptr<PointerEvent> pointerEvent, TaiheAxisValue& value);
    static int32_t GetPressedKey(const std::vector<int32_t>& pressedKeys, TaiheMouseEvent &mouseEvent);
};


using callbackType = std::variant<
    taihe::callback<bool(::ohos::multimodalInput::touchEvent::TouchEvent const&)>,
    taihe::callback<void(TaiheTouchEvent const &)>,
    taihe::callback<void(TaiheMouseEvent const &)>,
    taihe::callback<void(TaihePinchEvent const &)>,
    taihe::callback<void(TaiheRotate const &)>,
    taihe::callback<void(TaiheThreeFingersSwipe const &)>,
    taihe::callback<void(TaiheFourFingersSwipe const &)>,
    taihe::callback<void(TaiheThreeFingersTap const &)>,
    taihe::callback<void(TaiheFingerprintEvent const &)>,
    taihe::callback<void(TaiheSwipeInward const &)>,
    taihe::callback<void(TaiheTouchGestureEvent const &)>,
    taihe::callback<void(TaiheKeyEvent const &)>
    >;


struct CallbackObject {
    CallbackObject(callbackType cb, ani_ref ref) : callback(cb), ref(ref) {}
    ~CallbackObject()
    {
        if (auto *env = taihe::get_env()) {
            env->GlobalReference_Delete(ref);
        }
    }
    callbackType callback;
    ani_ref ref;
};

class GlobalRefGuard {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuard(ani_env *env, ani_object obj) : env_(env)
    {
        if (!env_) {
            return;
        }
        if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
            ref_ = nullptr;
        }
    }
    explicit operator bool() const
    {
        return ref_ != nullptr;
    }
    ani_ref get() const
    {
        return ref_;
    }
    ~GlobalRefGuard()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
        }
    }

    GlobalRefGuard(const GlobalRefGuard &) = delete;
    GlobalRefGuard &operator=(const GlobalRefGuard &) = delete;
};

} // namespace MMI
} // namespace OHOS
#endif // ANI_INPUT_TAIHE_INPUT_MONITOR_COMMON_H