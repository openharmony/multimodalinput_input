/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ohos.multimodalInput.inputMonitor.proj.hpp"
#include "ohos.multimodalInput.inputMonitor.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "ani_input_monitor_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputMonitorImpl"

namespace {
constexpr int32_t KEY_LIST_SIZE { 5 };
constexpr int32_t TWO_FINGERS { 2 };
constexpr int32_t THREE_FINGERS { 3 };
constexpr int32_t FOUR_FINGERS { 4 };
constexpr int32_t FIVE_FINGERS { 5 };
constexpr int32_t RECT_LIST_SIZE { 2 };
// To be implemented.
using namespace OHOS::MMI;
::taihe::array<::ohos::multimodalInput::touchEvent::TouchEvent> QueryTouchEventsSync(int32_t count)
{
    return ANI_INPUT_MONITOR_MGR.QueryTouchEvents(count);
}

void onTouchImpl(
    ::taihe::callback_view<bool(::ohos::multimodalInput::touchEvent::TouchEvent const& touchEvent)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_TOUCH_BOOL, param, receiver, opq);
}

void onMouseImpl(::taihe::callback_view<void(::ohos::multimodalInput::mouseEvent::MouseEvent const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_MOUSE, param, receiver, opq);
}

void onMouseForDisplayRect(uintptr_t rect,
    ::taihe::callback_view<void(::ohos::multimodalInput::mouseEvent::MouseEvent const& info)> receiver, uintptr_t opq)
{
    ani_object aniArray = reinterpret_cast<ani_object>(rect);
    if (aniArray == nullptr) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "inner error");
        return;
    }
    std::vector<Rect> rects;
    if (!TaiheMonitorConverter::ParseRects(aniArray, rects, RECT_LIST_SIZE)) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Hot Rect Area Parameter error");
        return;
    }
    ConsumerParmType param = rects;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_MOUSE_RECT, param, receiver, opq);
}

void onPinchImpl(
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::Pinch const& info)> receiver, uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_PINCH, param, receiver, opq);
}

void onPinchByNumber(int32_t fingers,
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::Pinch const& info)> receiver,
    uintptr_t opq)
{
    if (fingers < TWO_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ConsumerParmType param = fingers;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_PINCH_FINGERS, param, receiver, opq);
}

void onRotateByNumber(int32_t fingers,
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::Rotate const& info)> receiver,
    uintptr_t opq)
{
    if (fingers > TWO_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ConsumerParmType param = fingers;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_ROTATE_FINGERS, param, receiver, opq);
}

void onThreeFingersSwipeImpl(
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::ThreeFingersSwipe const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_THREEFINGERSWIPE, param, receiver, opq);
}

void onFourFingersSwipeImpl(
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::FourFingersSwipe const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_FOURFINGERSWIPE, param, receiver, opq);
}

void onThreeFingersTapImpl(
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::ThreeFingersTap const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_THREEFINGERSTAP, param, receiver, opq);
}

void onFingerprintImpl(
    ::taihe::callback_view<void(::ohos::multimodalInput::shortKey::FingerprintEvent const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_FINGERPRINT, param, receiver, opq);
}

void onSwipeInwardImpl(
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::SwipeInward const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_SWIPEINWARD, param, receiver, opq);
}

void onTouchscreenSwipeByNumber(int32_t fingers,
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::TouchGestureEvent const& info)> receiver,
    uintptr_t opq)
{
    if (fingers < THREE_FINGERS || fingers > FIVE_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ConsumerParmType param = fingers;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_TOUCHSCREENSWIPE_FINGERS, param, receiver, opq);
}

void onTouchscreenPinchImpl(int32_t fingers,
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::TouchGestureEvent const& info)> receiver,
    uintptr_t opq)
{
    if (fingers < FOUR_FINGERS || fingers > FIVE_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ConsumerParmType param = fingers;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_TOUCHSCREENPINCH_FINGERS, param, receiver, opq);
}

void onKeyPressedImpl(::taihe::array_view<::ohos::multimodalInput::keyCode::KeyCode> keys,
    ::taihe::callback_view<void(::ohos::multimodalInput::keyEvent::KeyEvent const& info)> receiver, uintptr_t opq)
{
    std::vector<int32_t> inputkeys;
    if (keys.size() <= 0 || keys.size() > KEY_LIST_SIZE) {
        MMI_HILOGE("keys Parameter error");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "keys Parameter error");
        return;
    }
    for (auto it = keys.begin(); it != keys.end(); ++it) {
        auto keyCode = static_cast<int32_t>(*it);
        if (false == ANI_INPUT_MONITOR_MGR.CheckKeyCode(keyCode)) {
            taihe::set_business_error(PRE_KEY_NOT_SUPPORTED, "Event listening not supported for the key");
            return;
        }
        inputkeys.push_back(keyCode);
    }
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_KEYPRESSED_KEYS, inputkeys, receiver, opq);
}

void offTouchImpl(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_TOUCH, receiver);
}

void offMouseImpl(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_MOUSE, receiver);
}

void offPinchImpl(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_PINCH, receiver);
}

void offPinchByNumber(int32_t fingers, ::taihe::optional_view<uintptr_t> receiver)
{
    if (fingers < TWO_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_PINCH_FINGERS, receiver, fingers);
}

void offRotateByNumber(int32_t fingers, ::taihe::optional_view<uintptr_t> receiver)
{
    if (fingers > TWO_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_ROTATE_FINGERS, receiver, fingers);
}

void offThreeFingersSwipeImpl(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_THREEFINGERSWIPE, receiver);
}

void offFourFingersSwipeImpl(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_FOURFINGERSWIPE, receiver);
}

void offThreeFingersTapImpl(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_THREEFINGERSTAP, receiver);
}

void offFingerprintImpl(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_FINGERPRINT, receiver);
}

void offSwipeInwardImpl(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_SWIPEINWARD, receiver);
}

void offTouchscreenSwipeImpl(int32_t fingers, ::taihe::optional_view<uintptr_t> receiver)
{
    if (fingers < THREE_FINGERS || fingers > FIVE_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_TOUCHSCREENSWIPE_FINGERS, receiver, fingers);
}

void offTouchscreenPinchImpl(int32_t fingers, ::taihe::optional_view<uintptr_t> receiver)
{
    if (fingers < FOUR_FINGERS || fingers > FIVE_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_TOUCHSCREENPINCH_FINGERS, receiver, fingers);
}

void offKeyPressedImpl(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_KEYPRESSED_KEYS, receiver);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_QueryTouchEventsSync(QueryTouchEventsSync);
TH_EXPORT_CPP_API_onTouchImpl(onTouchImpl);
TH_EXPORT_CPP_API_onMouseImpl(onMouseImpl);
TH_EXPORT_CPP_API_onMouseForDisplayRect(onMouseForDisplayRect);
TH_EXPORT_CPP_API_onPinchImpl(onPinchImpl);
TH_EXPORT_CPP_API_onPinchByNumber(onPinchByNumber);
TH_EXPORT_CPP_API_onRotateByNumber(onRotateByNumber);
TH_EXPORT_CPP_API_onThreeFingersSwipeImpl(onThreeFingersSwipeImpl);
TH_EXPORT_CPP_API_onFourFingersSwipeImpl(onFourFingersSwipeImpl);
TH_EXPORT_CPP_API_onThreeFingersTapImpl(onThreeFingersTapImpl);
TH_EXPORT_CPP_API_onFingerprintImpl(onFingerprintImpl);
TH_EXPORT_CPP_API_onSwipeInwardImpl(onSwipeInwardImpl);
TH_EXPORT_CPP_API_onTouchscreenSwipeByNumber(onTouchscreenSwipeByNumber);
TH_EXPORT_CPP_API_onTouchscreenPinchImpl(onTouchscreenPinchImpl);
TH_EXPORT_CPP_API_onKeyPressedImpl(onKeyPressedImpl);
TH_EXPORT_CPP_API_offTouchImpl(offTouchImpl);
TH_EXPORT_CPP_API_offMouseImpl(offMouseImpl);
TH_EXPORT_CPP_API_offPinchImpl(offPinchImpl);
TH_EXPORT_CPP_API_offPinchByNumber(offPinchByNumber);
TH_EXPORT_CPP_API_offRotateByNumber(offRotateByNumber);
TH_EXPORT_CPP_API_offThreeFingersSwipeImpl(offThreeFingersSwipeImpl);
TH_EXPORT_CPP_API_offFourFingersSwipeImpl(offFourFingersSwipeImpl);
TH_EXPORT_CPP_API_offThreeFingersTapImpl(offThreeFingersTapImpl);
TH_EXPORT_CPP_API_offFingerprintImpl(offFingerprintImpl);
TH_EXPORT_CPP_API_offSwipeInwardImpl(offSwipeInwardImpl);
TH_EXPORT_CPP_API_offTouchscreenSwipeImpl(offTouchscreenSwipeImpl);
TH_EXPORT_CPP_API_offTouchscreenPinchImpl(offTouchscreenPinchImpl);
TH_EXPORT_CPP_API_offKeyPressedImpl(offKeyPressedImpl);
// NOLINTEND
