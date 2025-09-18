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

#include "ani_input_monitor_common.h"

#include "define_multimodal.h"
#include "ohos.multimodalInput.keyCode.impl.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "aniMonitorCommon"

namespace OHOS {
namespace MMI {
int32_t TaiheMonitorConverter::TouchEventToTaihe(const PointerEvent &pointerEvent, TaiheTouchEvent &out)
{
    CALL_DEBUG_ENTER;
    auto ret = InputEventToTaihe(pointerEvent, out.base);
    CHKFR(ret == RET_OK, RET_ERR, "InputEventToTaihe failed");
    ret = TouchActionToTaihe(pointerEvent.GetPointerAction(), out.action);
    CHKFR(ret == RET_OK, RET_ERR, "TouchActionToTaihe failed");
    std::vector<TaiheTouch> vecTouches;
    for (auto item : pointerEvent.GetPointerIds()) {
        PointerEvent::PointerItem pointerItem;
        if (!pointerEvent.GetPointerItem(item, pointerItem)) {
            MMI_HILOGE("Get pointer item failed");
            return ret;
        }
        if (pointerItem.GetPointerId() == pointerEvent.GetPointerId()) {
            ret = TouchToTaihe(pointerItem, out.touch);
            if (ret!= RET_OK) {
                MMI_HILOGE("TouchToTaihe failed");
                return RET_ERR;
            }
        }
        auto taiheTouch = TaiheTouch {.toolType = TaiheToolType::key_t::FINGER};
        ret = TouchToTaihe(pointerItem, taiheTouch);
        if (ret!= RET_OK) {
            MMI_HILOGE("TouchToTaihe failed");
            return RET_ERR;
        }
        vecTouches.push_back(taiheTouch);
    }
    out.touches = taihe::array<TaiheTouch>(vecTouches);
    ret = SourceTypeToTaihe(pointerEvent.GetSourceType(), out.sourceType);
    if (ret!= RET_OK) {
        MMI_HILOGE("SourceTypeToTaihe failed");
        return RET_ERR;
    }
    auto fixedmode = TaiheFixedMode::from_value(RET_ERR);
    ret = FixedModeToTaihe(pointerEvent.GetFixedMode(), fixedmode);
    if (ret != RET_OK) {
        MMI_HILOGE("FixedModeToTaihe failed");
        return RET_ERR;
    }
    out.fixedMode = taihe::optional<TaiheFixedMode>(std::in_place_t{}, fixedmode);
    out.isInject = taihe::optional<bool>(std::in_place,
        const_cast<PointerEvent*>(&pointerEvent)->HasFlag(InputEvent::EVENT_FLAG_SIMULATE));
    return ret;
}

int32_t TaiheMonitorConverter::InputEventToTaihe(const InputEvent &inputEvent, TaiheInputEvent &out)
{
    out.id = inputEvent.GetId();
    out.deviceId = inputEvent.GetDeviceId();
    out.actionTime = inputEvent.GetActionTime();
    out.screenId = inputEvent.GetTargetDisplayId();
    out.windowId = inputEvent.GetTargetWindowId();
    return RET_OK;
}

int32_t TaiheMonitorConverter::TouchActionToTaihe(int32_t action, TaiheTouchAction &out)
{
    bool ret = RET_OK;
    switch (action) {
        case PointerEvent::POINTER_ACTION_CANCEL: {
            out = TaiheTouchAction::key_t::CANCEL;
            break;
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            out = TaiheTouchAction::key_t::DOWN;
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            out = TaiheTouchAction::key_t::MOVE;
            break;
        }
        case PointerEvent::POINTER_ACTION_UP: {
            out = TaiheTouchAction::key_t::UP;
            break;
        }
        // 0702 The value corresponding to pull_down pull_move pull_up is not defined in the code
        default: {
            ret = RET_ERR;
        }
    }
    return ret;
}

int32_t TaiheMonitorConverter::SourceTypeToTaihe(int32_t sourceType, TaiheSourceType &out)
{
    auto ret = RET_OK;
    switch (sourceType) {
        case PointerEvent::SOURCE_TYPE_TOUCHSCREEN: {
            out = TaiheSourceType::key_t::TOUCH_SCREEN;
            break;
        }
        case PointerEvent::SOURCE_TYPE_TOUCHPAD: {
            out = TaiheSourceType::key_t::TOUCH_PAD;
            break;
        }
        default: {
            ret = RET_ERR;
        }
    }
    return ret;
}

int32_t TaiheMonitorConverter::FixedModeToTaihe(PointerEvent::FixedMode fixedMode, TaiheFixedMode &out)
{
    auto ret = RET_OK;
    switch (fixedMode) {
        case PointerEvent::FixedMode::SCREEN_MODE_UNKNOWN: {
            out = TaiheFixedMode::key_t::NONE;
            break;
        }
        case PointerEvent::FixedMode::AUTO: {
            out = TaiheFixedMode::key_t::AUTO;
            break;
        }
        // 0702 The value of the corresponding TaiheTouchAction::key_t::PEN is not implemented in the code
        default: {
            ret = RET_ERR;
        }
    }
    return ret;
}

int32_t TaiheMonitorConverter::TouchToTaihe(const PointerEvent::PointerItem &item, TaiheTouch &out)
{
    out.id = item.GetPointerId();
    out.pressedTime = item.GetDownTime();
    out.screenX =  item.GetDisplayX();
    out.screenY = item.GetDisplayY();
    // 0702 The interface does not define globalX and globalY
    out.windowX = item.GetWindowX();
    out.windowY = item.GetWindowY();
    out.pressure = item.GetPressure();
    out.width = item.GetWidth();
    out.height = item.GetHeight();
    out.tiltX = item.GetTiltX();
    out.tiltY = item.GetTiltY();
    out.toolX = item.GetToolDisplayX();
    out.toolY = item.GetToolDisplayY();
    out.toolWidth = item.GetToolWidth();
    out.toolHeight = item.GetToolHeight();
    out.rawX = item.GetRawDx();
    out.rawY = item.GetRawDy();
    out.toolType.from_value(item.GetToolType());
    out.fixedDisplayX = taihe::optional<int32_t>(std::in_place_t{}, item.GetFixedDisplayX());
    out.fixedDisplayY = taihe::optional<int32_t>(std::in_place_t{}, item.GetFixedDisplayY());
    return RET_OK;
}

int32_t TaiheMonitorConverter::TouchGestureActionToTaihe(int32_t action, TaiheTouchGestureAction &out)
{
    auto ret = RET_OK;
    switch (action) {
        case PointerEvent::TOUCH_ACTION_SWIPE_DOWN: {
            out = TaiheTouchGestureAction::key_t::SWIPE_DOWN;
            break;
        }
        case PointerEvent::TOUCH_ACTION_SWIPE_UP: {
            out = TaiheTouchGestureAction::key_t::SWIPE_UP;
            break;
        }
        case PointerEvent::TOUCH_ACTION_SWIPE_RIGHT: {
            out = TaiheTouchGestureAction::key_t::SWIPE_RIGHT;
            break;
        }
        case PointerEvent::TOUCH_ACTION_SWIPE_LEFT: {
            out = TaiheTouchGestureAction::key_t::SWIPE_LEFT;
            break;
        }
        case PointerEvent::TOUCH_ACTION_PINCH_OPENED: {
            out = TaiheTouchGestureAction::key_t::PINCH_OPENED;
            break;
        }
        case PointerEvent::TOUCH_ACTION_PINCH_CLOSEED: {
            out = TaiheTouchGestureAction::key_t::PINCH_CLOSED;
            break;
        }
        case PointerEvent::TOUCH_ACTION_GESTURE_END: {
            out = TaiheTouchGestureAction::key_t::GESTURE_END;
            break;
        }
        default: {
            MMI_HILOGW("unknow action, action:%{public}d", action);
            ret = RET_ERR;
        }
    }
    return ret;
}

int32_t TaiheMonitorConverter::RotateActionToTaihe(int32_t action, TaiheGestureActionType &out)
{
    auto ret = RET_OK;
    switch (action) {
        case PointerEvent::POINTER_ACTION_ROTATE_BEGIN: {
            out = TaiheGestureActionType::key_t::BEGIN;
            break;
        }
        case PointerEvent::POINTER_ACTION_ROTATE_UPDATE: {
            out = TaiheGestureActionType::key_t::UPDATE;
            break;
        }
        case PointerEvent::POINTER_ACTION_ROTATE_END: {
            out = TaiheGestureActionType::key_t::END;
            break;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action in rotate event");
            ret = RET_ERR;
        }
    }
    return ret;
}

int32_t TaiheMonitorConverter::PinchActionToTaihe(int32_t action, TaiheGestureActionType &out)
{
    auto ret = RET_OK;
    switch (action) {
        case PointerEvent::POINTER_ACTION_AXIS_BEGIN: {
            out = TaiheGestureActionType::key_t::BEGIN;
            break;
        }
        case PointerEvent::POINTER_ACTION_AXIS_UPDATE: {
            out = TaiheGestureActionType::key_t::UPDATE;
            break;
        }
        case PointerEvent::POINTER_ACTION_AXIS_END: {
            out = TaiheGestureActionType::key_t::END;
            break;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action in pinch event");
            ret = RET_ERR;
        }
    }
    return ret;
}

int32_t TaiheMonitorConverter::SwipeInwardActionToTaihe(int32_t action, TaiheGestureActionType &out)
{
    auto ret = RET_OK;
    switch (action) {
        case PointerEvent::POINTER_ACTION_DOWN: {
            out = TaiheGestureActionType::key_t::BEGIN;
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            out = TaiheGestureActionType::key_t::UPDATE;
            break;
        }
        case PointerEvent::POINTER_ACTION_UP:
        case PointerEvent::POINTER_ACTION_CANCEL: {
            out = TaiheGestureActionType::key_t::END;
            break;
        }
        default: {
            MMI_HILOGE("Abnormal pointer action in swipe event");
            ret = RET_ERR;
        }
    }
    return ret;
}

int32_t TaiheMonitorConverter::SwipeActionToTaihe(int32_t action, TaiheGestureActionType &out)
{
    auto ret = RET_OK;
    switch (action) {
        case PointerEvent::POINTER_ACTION_SWIPE_BEGIN: {
            out = TaiheGestureActionType::key_t::BEGIN;
            break;
        }
        case PointerEvent::POINTER_ACTION_SWIPE_UPDATE: {
            out = TaiheGestureActionType::key_t::UPDATE;
            break;
        }
        case PointerEvent::POINTER_ACTION_SWIPE_END: {
            out = TaiheGestureActionType::key_t::END;
            break;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action in swipe event");
            ret = RET_ERR;
        }
    }
    return ret;
}

int32_t TaiheMonitorConverter::MultiTapActionToTaihe(int32_t action, TaiheGestureActionType &out)
{
    auto ret = RET_OK;
    switch (action) {
        case PointerEvent::POINTER_ACTION_TRIPTAP: {
            out = TaiheGestureActionType::key_t::END;
            break;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action in multi tap event");
            ret = RET_ERR;
        }
    }
    return ret;
}

int32_t TaiheMonitorConverter::RotateToTaihe(const PointerEvent &pointerEvent, TaiheRotate &out)
{
    auto type = TaiheGestureActionType::from_value(RET_ERR);
    auto ret = RotateActionToTaihe(pointerEvent.GetPointerAction(), type);
    if (ret != RET_OK) {
        return ret;
    }
    out.type = type;
    out.angle = pointerEvent.GetAxisValue(PointerEvent::AXIS_TYPE_ROTATE);
    return ret;
}

int32_t TaiheMonitorConverter::PinchToTaihe(const PointerEvent &pointerEvent, TaihePinchEvent &out)
{
    auto type = TaiheGestureActionType::from_value(RET_ERR);
    auto ret = PinchActionToTaihe(pointerEvent.GetPointerAction(), type);
    if (ret != RET_OK) {
        return ret;
    }
    out.type = type;
    out.scale = pointerEvent.GetAxisValue(PointerEvent::AXIS_TYPE_PINCH);
    return ret;
}

int32_t TaiheMonitorConverter::SwipeInwardToTaihe(const PointerEvent &pointerEvent, TaiheSwipeInward &out)
{
    auto type = TaiheGestureActionType::from_value(RET_ERR);
    auto ret = SwipeActionToTaihe(pointerEvent.GetPointerAction(), type);
    if (ret != RET_OK) {
        return ret;
    }
    out.type = type;
    PointerEvent::PointerItem pointeritem;
    int32_t pointerId = 0;
    ret = pointerEvent.GetPointerItem(pointerId, pointeritem);
    if (ret != RET_OK) {
        MMI_HILOGE("Can't find this pointerItem");
        return ret;
    }
    out.x =  pointeritem.GetDisplayX();
    out.y =  pointeritem.GetDisplayY();
    return ret;
}

int32_t TaiheMonitorConverter::ThreeFingersSwipeToTaihe(const PointerEvent &pointerEvent, TaiheThreeFingersSwipe &out)
{
    auto type = TaiheGestureActionType::from_value(RET_ERR);
    auto ret = SwipeActionToTaihe(pointerEvent.GetPointerAction(), type);
    if (ret != RET_OK) {
        MMI_HILOGE("SwipeActionToTaihe error");
        return ret;
    }
    out.type = type;
    PointerEvent::PointerItem pointeritem;
    int32_t pointerId = 0;
    ret = pointerEvent.GetPointerItem(pointerId, pointeritem);
    if (ret != RET_OK) {
        MMI_HILOGE("Can't find this pointerItem");
        return ret;
    }
    out.x =  pointeritem.GetDisplayX();
    out.y =  pointeritem.GetDisplayY();
    return ret;
}

int32_t TaiheMonitorConverter::FourFingersSwipeToTaihe(const PointerEvent &pointerEvent, TaiheFourFingersSwipe &out)
{
    auto type = TaiheGestureActionType::from_value(RET_ERR);
    auto ret = SwipeActionToTaihe(pointerEvent.GetPointerAction(), type);
    if (ret != RET_OK) {
        MMI_HILOGE("SwipeActionToTaihe error");
        return ret;
    }
    out.type = type;
    PointerEvent::PointerItem pointeritem;
    int32_t pointerId = 0;
    ret = pointerEvent.GetPointerItem(pointerId, pointeritem);
    if (ret != RET_OK) {
        MMI_HILOGE("Can't find this pointerItem");
        return ret;
    }
    out.x =  pointeritem.GetDisplayX();
    out.y =  pointeritem.GetDisplayY();
    return ret;
}

int32_t TaiheMonitorConverter::TouchGestureEventToTaihe(const PointerEvent &pointerEvent, TaiheTouchGestureEvent &out)
{
    auto action = TaiheTouchGestureAction::from_value(RET_ERR);
    auto ret = TouchGestureActionToTaihe(pointerEvent.GetPointerAction(), action);
    if (ret != RET_OK) {
        MMI_HILOGE("TouchGestureActionToTaihe error");
        return ret;
    }
    out.action = action;
    std::vector<TaiheTouch> vecTouches;
    for (auto item : pointerEvent.GetPointerIds()) {
        PointerEvent::PointerItem pointerItem;
        ret = pointerEvent.GetPointerItem(item, pointerItem);
        if (ret != RET_OK) {
            MMI_HILOGE("Get pointer item failed");
            return ret;
        }
        TaiheTouch per {.toolType = TaiheToolType::key_t::FINGER};
        ret = TouchToTaihe(pointerItem, per);
        if (ret != RET_OK) {
            MMI_HILOGE("TouchToTaihe failed");
            return ret;
        }
        vecTouches.push_back(per);
    }
    out.touches = taihe::array<TaiheTouch>(vecTouches);
    return ret;
}

int32_t TaiheMonitorConverter::ThreeFingersTapToTaihe(const PointerEvent &pointerEvent, TaiheThreeFingersTap &out)
{
    auto type = TaiheGestureActionType::from_value(RET_ERR);
    auto ret = MultiTapActionToTaihe(pointerEvent.GetPointerAction(), type);
    if (ret != RET_OK) {
        MMI_HILOGE("SwipeActionToTaihe error");
        return ret;
    }
    out.type = type;
    return ret;
}

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
int32_t TaiheMonitorConverter::FingerprintActionToTaihe(int32_t action, TaiheFingerprintAction &out)
{
    auto ret = RET_OK;
    switch (action) {
        case PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN: {
            out = TaiheFingerprintAction::key_t::DOWN;
            break;
        }
        case PointerEvent::POINTER_ACTION_FINGERPRINT_UP: {
            out = TaiheFingerprintAction::key_t::UP;
            break;
        }
        case PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE: {
            out = TaiheFingerprintAction::key_t::SLIDE;
            break;
        }
        case PointerEvent::POINTER_ACTION_FINGERPRINT_RETOUCH: {
            out = TaiheFingerprintAction::key_t::RETOUCH;
            break;
        }
        case PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK: {
            out = TaiheFingerprintAction::key_t::CLICK;
            break;
        }
        // 0702 The interface definition is not found POINTER_ACTION_FINGERPRINT_CANCEL,
        // POINTER_ACTION_FINGERPRINT_HOLD,POINTER_ACTION_FINGERPRINT_TOUCH
        default: {
            MMI_HILOGE("Wrong action is %{public}d", action);
            ret = RET_ERR;
        }
    }
}

int32_t TaiheMonitorConverter::FingerprintEventToTaihe(const PointerEvent &pointerEvent, TaiheFingerprintEvent &out)
{
    auto type = TaiheFingerprintAction::from_value(RET_ERR);
    auto ret = FingerprintActionToTaihe(pointerEvent.GetPointerAction(), type);
    if (ret != RET_OK) {
        MMI_HILOGE("TouchGestureActionToTaihe error");
        return ret;
    }
    out.action = type;
    out.distanceX = pointerEvent.GetFingerprintDistanceX();
    out.distanceY = pointerEvent.GetFingerprintDistanceY();
    return ret;
}
#endif

bool TaiheMonitorConverter::HasKeyCode(const std::vector<int32_t>& pressedKeys, int32_t keyCode)
{
    return std::find(pressedKeys.begin(), pressedKeys.end(), keyCode) != pressedKeys.end();
}

int32_t TaiheMonitorConverter::KeyEventActionToTaihe(int32_t action, TaiheKeyEventAction &out)
{
    auto ret = RET_OK;
    if (KeyEvent::KEY_ACTION_CANCEL == action) {
        out = TaiheKeyEventAction::key_t::CANCEL;
    } else if (KeyEvent::KEY_ACTION_DOWN == action) {
        out = TaiheKeyEventAction::key_t::DOWN;
    } else if (KeyEvent::KEY_ACTION_UP == action) {
        out = TaiheKeyEventAction::key_t::UP;
    } else {
        ret = RET_ERR;
    }
    return ret;
}

int32_t TaiheMonitorConverter::TaiheKeyEventToTaihe(const KeyEvent &keyEvent, TaiheKeyEvent &out)
{
    CALL_DEBUG_ENTER;
    auto action = TaiheKeyEventAction::from_value(RET_ERR);
    auto ret = KeyEventActionToTaihe(keyEvent.GetKeyAction(), action);
    CHKFR(ret == RET_OK, ret, "TaiheKeyEventToTaihe error");
    std::optional<KeyEvent::KeyItem> keyItem = keyEvent.GetKeyItem();
    CHKFR(keyItem != std::nullopt, RET_ERR, "The keyItem is nullopt");
    ret = TaiheKeyEventKeyToTaihe(keyItem.value(), out.key);
    CHKFR(ret == RET_OK, ret, "TaiheKeyEventToTaihe error");
    out.unicodeChar = keyItem->GetUnicode();
    std::vector<int32_t> pressedKeys = keyEvent.GetPressedKeys();
    std::vector<TaiheKeyEventKey> keys;
    for (const auto &pressedKeyCode : pressedKeys) {
        std::optional<KeyEvent::KeyItem> pressedKeyItem = keyEvent.GetKeyItem(pressedKeyCode);
        CHKFR(pressedKeyItem != std::nullopt, RET_ERR, "The pressedKeyItem is nullopt");
        auto taiheKey = TaiheKeyEventKey{ .code = KeyCode::key_t::KEYCODE_UNKNOWN };
        ret = TaiheKeyEventKeyToTaihe(pressedKeyItem.value(), taiheKey);
        CHKFR(ret == RET_OK, ret, "TaiheKeyEventToTaihe error");
        keys.push_back(taiheKey);
    }
    out.keys = taihe::array<TaiheKeyEventKey>(keys);
    ret = InputEventToTaihe(keyEvent, out.base);
    CHKFR(ret == RET_OK, ret, "TaiheKeyEventToTaihe error");
    ret = InputEventToTaihe(keyEvent, out.base);
    CHKFR(ret == RET_OK, ret, "TaiheKeyEventToTaihe error");
    out.ctrlKey = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_RIGHT);
    out.altKey = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_RIGHT);;
    out.shiftKey =  HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_RIGHT);
    out.logoKey = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_RIGHT);
    out.fnKey = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_FN);
    out.capsLock = keyEvent.GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY);
    out.numLock =  keyEvent.GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY);
    out.scrollLock = keyEvent.GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY);
    return ret;
}

int32_t TaiheMonitorConverter::TaiheKeyEventKeyToTaihe(const KeyEvent::KeyItem &keyItem, TaiheKeyEventKey &out)
{
    auto ret = RET_OK;
    out.code = TaiheKeyCodeConverter::ConvertEtsKeyCode(keyItem.GetKeyCode());
    out.pressedTime = keyItem.GetDownTime();
    out.deviceId = keyItem.GetDeviceId();
    return ret;
}

int32_t TaiheMonitorConverter::SetMouseProperty(std::shared_ptr<PointerEvent>& pointerEvent,
    const PointerEvent::PointerItem& item, TaiheMouseEvent &mouseEvent)
{
    int32_t ret = RET_OK;
    int32_t buttonId = pointerEvent->GetButtonId();
    if (buttonId == PointerEvent::MOUSE_BUTTON_MIDDLE) {
        buttonId = TH_MOUSE_BUTTON::JS_MOUSE_BUTTON_MIDDLE;
    } else if (buttonId == PointerEvent::MOUSE_BUTTON_RIGHT) {
        buttonId = TH_MOUSE_BUTTON::JS_MOUSE_BUTTON_RIGHT;
    }

    mouseEvent.button = TaiheMouseButton::key_t(buttonId);
    mouseEvent.base.actionTime = pointerEvent->GetActionTime();
    mouseEvent.base.deviceId = item.GetDeviceId();
    mouseEvent.base.screenId = pointerEvent->GetTargetDisplayId();
    mouseEvent.base.windowId = pointerEvent->GetTargetWindowId();
    mouseEvent.base.deviceId = item.GetDeviceId();
    mouseEvent.screenX = item.GetDisplayX();
    mouseEvent.screenY = item.GetDisplayY();
    mouseEvent.windowX = item.GetWindowX();
    mouseEvent.windowY = item.GetWindowY();
    mouseEvent.rawDeltaX = item.GetRawDx();
    mouseEvent.rawDeltaY = item.GetRawDy();
    // 0702 The interface is not defined globalX, globalY
    // 0702  No implementation found in the code pressedKeys,ctrlKey,
    // altKey,shiftKey,logoKey,fnKey,capsLock,numLock,scrollLock,toolType
    return ret;
}

int32_t TaiheMonitorConverter::GetAxesValue(const std::shared_ptr<PointerEvent> pointerEvent, TaiheAxisValue& value)
{
    double axisValue = -1.0;
    int32_t axis = -1;
    if (pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL);
        axis = AXIS_TYPE_SCROLL_VERTICAL;
    }
    if (pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL);
        axis = AXIS_TYPE_SCROLL_HORIZONTAL;
    }
    if (pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_PINCH)) {
        axisValue = pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH);
        axis = AXIS_TYPE_PINCH;
    }

    value.axis = TaiheAxis::key_t(axis) ;
    value.value = axisValue;

    return RET_OK;
}

int32_t TaiheMonitorConverter::GetMousePointerItem(
    std::shared_ptr<PointerEvent> pointerEvent, TaiheMouseEvent &mouseEvent)
{
    int32_t ret = RET_OK;
    int32_t currentPointerId = pointerEvent->GetPointerId();
    std::vector<TaiheAxisValue> axisValueVec;
    std::vector<int32_t> pointerIds { pointerEvent->GetPointerIds() };
    for (const auto& pointerId : pointerIds) {
        if (pointerId == currentPointerId) {
            PointerEvent::PointerItem item;
            if (!pointerEvent->GetPointerItem(pointerId, item)) {
                MMI_HILOGE("Invalid pointer:%{public}d", pointerId);
                ret = RET_ERR;
                return ret;
            }
            mouseEvent.base.id = currentPointerId;
            SetMouseProperty(pointerEvent, item, mouseEvent);
        }

        TaiheAxisValue value = {.axis = TaiheAxis::key_t(0), .value = 0};
        GetAxesValue(pointerEvent, value);
        axisValueVec.push_back(value);
    }

    mouseEvent.axes = taihe::array<TaiheAxisValue>(axisValueVec);
    return  ret;
}

int32_t TaiheMonitorConverter::GetPressedKey(const std::vector<int32_t>& pressedKeys, TaiheMouseEvent &mouseEvent)
{
    int32_t ret = RET_OK;
    bool isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_RIGHT);
    mouseEvent.ctrlKey = isExists;

    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_RIGHT);
    mouseEvent.altKey = isExists;

    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_RIGHT);
    mouseEvent.shiftKey = isExists;

    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_LEFT)
        || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_RIGHT);
    mouseEvent.logoKey = isExists;

    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_FN);
    mouseEvent.fnKey = isExists;
    return ret;
}

int32_t TaiheMonitorConverter::MouseActionToTaihe(int32_t action, TaiheMouseAction &out)
{
    int32_t ret = RET_OK;
    switch (action) {
        case PointerEvent::POINTER_ACTION_CANCEL: {
            out = TaiheMouseAction::key_t::CANCEL;
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE:
        case PointerEvent::POINTER_ACTION_PULL_MOVE: {
            out = TaiheMouseAction::key_t::MOVE;
            break;
        }
        case PointerEvent::POINTER_ACTION_BUTTON_DOWN:
        case PointerEvent::POINTER_ACTION_PULL_DOWN: {
            out = TaiheMouseAction::key_t::BUTTON_DOWN;
            break;
        }
        case PointerEvent::POINTER_ACTION_BUTTON_UP:
        case PointerEvent::POINTER_ACTION_PULL_UP: {
            out = TaiheMouseAction::key_t::BUTTON_UP;
            break;
        }
        case PointerEvent::POINTER_ACTION_AXIS_BEGIN: {
            out = TaiheMouseAction::key_t::AXIS_BEGIN;
            break;
        }
        case PointerEvent::POINTER_ACTION_AXIS_UPDATE: {
            out = TaiheMouseAction::key_t::AXIS_UPDATE;
            break;
        }
        case PointerEvent::POINTER_ACTION_AXIS_END: {
            out = TaiheMouseAction::key_t::AXIS_END;
            break;
        }
        default: {
            MMI_HILOGD("Abnormal pointer action");
            ret = RET_ERR;
        }
        // 0702 The translation lacks the interface layer Action_down, Action_up,
    }
    return ret;
}

int32_t TaiheMonitorConverter::MouseEventToTaihe(std::shared_ptr<PointerEvent> pointerEvent, TaiheMouseEvent &out)
{
    int32_t ret = MouseActionToTaihe(pointerEvent->GetPointerAction(), out.action);
    if (ret != RET_OK) {
        return ret;
    }
    std::vector<int32_t> pressedKeys = pointerEvent->GetPressedKeys();
    std::vector<TaiheKeyCode> pressedKeysVec;
    for (auto& value: pressedKeys) {
        TaiheKeyCode code = TaiheKeyCode::key_t(value);
        pressedKeysVec.push_back(code);
    }
    out.pressedKeys = taihe::array<TaiheKeyCode>(pressedKeysVec);

    ret = GetPressedKey(pressedKeys, out);
    if (ret != RET_OK) {
        MMI_HILOGE("Get singlePressedKey failed");
        return ret;
    }
    ret = GetMousePointerItem(pointerEvent, out);
    if (ret != RET_OK) {
        MMI_HILOGE("Get item of mousePointer failed");
        return ret;
    }
    std::set<int32_t> pressedButtons = pointerEvent->GetPressedButtons();
    std::vector<TaiheMouseButton> pressedButtonsVec;
    for (auto& item : pressedButtons) {
        auto buttonId = TaiheMouseButton::key_t(item);
        if (item == PointerEvent::MOUSE_BUTTON_MIDDLE) {
            buttonId = TaiheMouseButton::key_t::MIDDLE;
        } else if (item == PointerEvent::MOUSE_BUTTON_RIGHT) {
            buttonId = TaiheMouseButton::key_t::RIGHT;
        }
        pressedButtonsVec.push_back(buttonId);
    }

    out.pressedButtons = taihe::array<TaiheMouseButton>(pressedButtonsVec);
    return ret;
}

bool TaiheMonitorConverter::GetIntObject(ani_env* env, const char* propertyName,
    ani_object object, int32_t& result)
{
    ani_long value;
    ani_status ret = env->Object_GetPropertyByName_Long(object, propertyName, &value);
    if (ret != ANI_OK) {
        MMI_HILOGE("Object_GetPropertyByName_Long %{public}s Failed, ret : %{public}u",
            propertyName, static_cast<int32_t>(ret));
        return false;
    }
    result = static_cast<int32_t>(value);
    return true;
}

bool TaiheMonitorConverter::ParseRect(ani_env *env, ani_object rect, Rect &result)
{
    if (rect == nullptr) {
        MMI_HILOGE("AniObject is null");
        return false;
    }
    bool ret_bool = GetIntObject(env, "left", rect, result.x);
    ret_bool |= GetIntObject(env, "top", rect, result.y);
    ret_bool |= GetIntObject(env, "width", rect, result.width);
    ret_bool |= GetIntObject(env, "height", rect, result.height);
    if (!ret_bool) {
        MMI_HILOGE("GetIntObject Failed");
        return false;
    }
    MMI_HILOGD("rect is [%{public}d, %{public}d, %{public}d, %{public}d]",
        result.x, result.y, result.width, result.height);
    if (result.x < 0 || result.y < 0 || result.width < 0 || result.height < 0) {
        MMI_HILOGE("Rect parameter can't be negative.");
        return false;
    }
    return true;
}

bool TaiheMonitorConverter::ParseRects(ani_object aniRects, std::vector<Rect> &rects, int32_t maxNum)
{
    ani_status status = ANI_ERROR;
    auto *env = taihe::get_env();
    if (env == nullptr) {
        MMI_HILOGE("Failed to get ani env");
        return false;
    }
    ani_array aniArray = reinterpret_cast<ani_array>(aniRects);
    if (aniArray == nullptr) {
        MMI_HILOGE("Failed to change ani array");
        return false;
    }
    ani_size size;
    if ((status = env->Array_GetLength(aniArray, &size)) != ANI_OK) {
        MMI_HILOGE("Failed to get ani array length, status:%{public}d.", status);
        return false;
    }

    if (size <= 0 || size > static_cast<ani_size>(maxNum)) {
        MMI_HILOGE("Exceed maximum rects limit, rects size: %{public}zu", size);
        return false;
    }

    for (ani_size i = 0; i < size; i++) {
        ani_ref rectRef;
        status = env->Array_Get(aniArray, i, &rectRef);
        if (status != ANI_OK) {
            MMI_HILOGE("Get rect ref failed, i:%{public}d ret: %{public}d", i, status);
            return false;
        }
        Rect per;
        if (!ParseRect(env, static_cast<ani_object>(rectRef), per)) {
            MMI_HILOGE("Parse rect failed, i:%{public}d", i);
            return false;
        }
        rects.push_back(per);
    }
    return true;
}
} // namespace MMI
} // namespace OHOS