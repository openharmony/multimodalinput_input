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

void onTouch(
    ::taihe::callback_view<bool(::ohos::multimodalInput::touchEvent::TouchEvent const& touchEvent)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_TOUCH_BOOL, param, receiver, opq);
}

void onMouse(::taihe::callback_view<void(::ohos::multimodalInput::mouseEvent::MouseEvent const& info)> receiver,
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

void onPinch(
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

void onThreeFingersSwipe(
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::ThreeFingersSwipe const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_THREEFINGERSWIPE, param, receiver, opq);
}

void onFourFingersSwipe(
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::FourFingersSwipe const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_FOURFINGERSWIPE, param, receiver, opq);
}

void onThreeFingersTap(
    ::taihe::callback_view<void(::ohos::multimodalInput::gestureEvent::ThreeFingersTap const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_THREEFINGERSTAP, param, receiver, opq);
}

void onFingerprint(
    ::taihe::callback_view<void(::ohos::multimodalInput::shortKey::FingerprintEvent const& info)> receiver,
    uintptr_t opq)
{
    ConsumerParmType param;
    ANI_INPUT_MONITOR_MGR.AddMonitor(MONITORFUNTYPE::ON_FINGERPRINT, param, receiver, opq);
}

void onSwipeInward(
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

void onTouchscreenPinch(int32_t fingers,
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

void onKeyPressed(::taihe::array_view<::ohos::multimodalInput::keyCode::KeyCode> keys,
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

void offTouch(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_TOUCH, receiver);
}

void offMouse(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_MOUSE, receiver);
}

void offPinch(::taihe::optional_view<uintptr_t> receiver)
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

void offThreeFingersSwipe(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_THREEFINGERSWIPE, receiver);
}

void offFourFingersSwipe(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_FOURFINGERSWIPE, receiver);
}

void offThreeFingersTap(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_THREEFINGERSTAP, receiver);
}

void offFingerprint(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_FINGERPRINT, receiver);
}

void offSwipeInward(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_SWIPEINWARD, receiver);
}

void offTouchscreenSwipe(int32_t fingers, ::taihe::optional_view<uintptr_t> receiver)
{
    if (fingers < THREE_FINGERS || fingers > FIVE_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_TOUCHSCREENSWIPE_FINGERS, receiver, fingers);
}

void offTouchscreenPinch(int32_t fingers, ::taihe::optional_view<uintptr_t> receiver)
{
    if (fingers < FOUR_FINGERS || fingers > FIVE_FINGERS) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "fingers is invalid");
        return;
    }
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_TOUCHSCREENPINCH_FINGERS, receiver, fingers);
}

void offKeyPressed(::taihe::optional_view<uintptr_t> receiver)
{
    ANI_INPUT_MONITOR_MGR.RemoveMonitor(MONITORFUNTYPE::OFF_KEYPRESSED_KEYS, receiver);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_QueryTouchEventsSync(QueryTouchEventsSync);
TH_EXPORT_CPP_API_onTouch(onTouch);
TH_EXPORT_CPP_API_onMouse(onMouse);
TH_EXPORT_CPP_API_onMouseForDisplayRect(onMouseForDisplayRect);
TH_EXPORT_CPP_API_onPinch(onPinch);
TH_EXPORT_CPP_API_onPinchByNumber(onPinchByNumber);
TH_EXPORT_CPP_API_onRotateByNumber(onRotateByNumber);
TH_EXPORT_CPP_API_onThreeFingersSwipe(onThreeFingersSwipe);
TH_EXPORT_CPP_API_onFourFingersSwipe(onFourFingersSwipe);
TH_EXPORT_CPP_API_onThreeFingersTap(onThreeFingersTap);
TH_EXPORT_CPP_API_onFingerprint(onFingerprint);
TH_EXPORT_CPP_API_onSwipeInward(onSwipeInward);
TH_EXPORT_CPP_API_onTouchscreenSwipeByNumber(onTouchscreenSwipeByNumber);
TH_EXPORT_CPP_API_onTouchscreenPinch(onTouchscreenPinch);
TH_EXPORT_CPP_API_onKeyPressed(onKeyPressed);
TH_EXPORT_CPP_API_offTouch(offTouch);
TH_EXPORT_CPP_API_offMouse(offMouse);
TH_EXPORT_CPP_API_offPinch(offPinch);
TH_EXPORT_CPP_API_offPinchByNumber(offPinchByNumber);
TH_EXPORT_CPP_API_offRotateByNumber(offRotateByNumber);
TH_EXPORT_CPP_API_offThreeFingersSwipe(offThreeFingersSwipe);
TH_EXPORT_CPP_API_offFourFingersSwipe(offFourFingersSwipe);
TH_EXPORT_CPP_API_offThreeFingersTap(offThreeFingersTap);
TH_EXPORT_CPP_API_offFingerprint(offFingerprint);
TH_EXPORT_CPP_API_offSwipeInward(offSwipeInward);
TH_EXPORT_CPP_API_offTouchscreenSwipe(offTouchscreenSwipe);
TH_EXPORT_CPP_API_offTouchscreenPinch(offTouchscreenPinch);
TH_EXPORT_CPP_API_offKeyPressed(offKeyPressed);
// NOLINTEND
