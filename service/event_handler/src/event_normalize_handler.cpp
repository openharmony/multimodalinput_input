/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "event_normalize_handler.h"

#include "bytrace_adapter.h"
#include "crown_transform_processor.h"
#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "error_multimodal.h"
#include "event_log_helper.h"
#ifdef OHOS_BUILD_ENABLE_TOUCH
#include "event_resample.h"
#endif // OHOS_BUILD_ENABLE_TOUCH
#include "event_statistic.h"
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
#include "fingerprint_event_processor.h"
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_scene_board_judgement.h"
#include "key_auto_repeat.h"
#include "key_event_normalize.h"
#include "key_event_value_transformation.h"
#ifdef SHORTCUT_KEY_MANAGER_ENABLED
#include "key_shortcut_manager.h"
#endif // SHORTCUT_KEY_MANAGER_ENABLED
#include "libinput_adapter.h"
#include "mmi_log.h"
#include "multimodal_input_preferences_manager.h"
#include "time_cost_chk.h"
#include "timer_manager.h"
#include "touch_event_normalize.h"
#ifdef OHOS_BUILD_ENABLE_POINTER
#include "touchpad_transform_processor.h"
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_RSS_CLIENT
#include "res_sched_client.h"
#include "res_type.h"
#endif // OHOS_RSS_CLIENT

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventNormalizeHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t FINGER_NUM { 2 };
constexpr int32_t SWIPE_INWARD_FINGER_ONE { 1 };
constexpr int32_t USELIB_ABS_MT_POSITION_X { 0x35 };
constexpr int32_t USELIB_ABS_MT_POSITION_Y { 0x36 };
constexpr int32_t SWIPE_INWARD_EDGE_X_THRE { 8 };
constexpr int32_t SWIPE_INWARD_ANGLE_TOLERANCE { 8 };
constexpr int32_t TABLET_PRODUCT_DEVICE_ID { 4274 };
constexpr int32_t BLE_PRODUCT_DEVICE_ID { 4307 };
double g_touchPadDeviceWidth { 1 }; // physic size
double g_touchPadDeviceHeight { 1 };
int32_t g_touchPadDeviceAxisX { 1 }; // max axis size
int32_t g_touchPadDeviceAxisY { 1 };
bool g_isSwipeInward = false;
constexpr int32_t SWIPE_INWARD_ANGLE_JUDGE { 2 };
constexpr int32_t MT_TOOL_PALM { 2 };
[[ maybe_unused ]] constexpr double TOUCH_SLOP { 1.0 };
[[ maybe_unused ]] constexpr int32_t SQUARE { 2 };
[[ maybe_unused ]] constexpr double DENSITY_BASELINE { 160.0 };
const std::vector<int32_t> ALL_EVENT_TYPES = {
    static_cast<int32_t>(LIBINPUT_EVENT_DEVICE_ADDED),
    static_cast<int32_t>(LIBINPUT_EVENT_DEVICE_REMOVED),
    static_cast<int32_t>(LIBINPUT_EVENT_KEYBOARD_KEY),
    static_cast<int32_t>(LIBINPUT_EVENT_POINTER_MOTION),
    static_cast<int32_t>(LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE),
    static_cast<int32_t>(LIBINPUT_EVENT_POINTER_BUTTON),
    static_cast<int32_t>(LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD),
    static_cast<int32_t>(LIBINPUT_EVENT_POINTER_AXIS),
    static_cast<int32_t>(LIBINPUT_EVENT_POINTER_TAP),
    static_cast<int32_t>(LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD),
    static_cast<int32_t>(LIBINPUT_EVENT_TOUCHPAD_DOWN),
    static_cast<int32_t>(LIBINPUT_EVENT_TOUCHPAD_UP),
    static_cast<int32_t>(LIBINPUT_EVENT_TOUCHPAD_MOTION),
    static_cast<int32_t>(LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN),
    static_cast<int32_t>(LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE),
    static_cast<int32_t>(LIBINPUT_EVENT_GESTURE_SWIPE_END),
    static_cast<int32_t>(LIBINPUT_EVENT_GESTURE_PINCH_BEGIN),
    static_cast<int32_t>(LIBINPUT_EVENT_GESTURE_PINCH_UPDATE),
    static_cast<int32_t>(LIBINPUT_EVENT_GESTURE_PINCH_END),
    static_cast<int32_t>(LIBINPUT_EVENT_TOUCH_DOWN),
    static_cast<int32_t>(LIBINPUT_EVENT_TOUCH_UP),
    static_cast<int32_t>(LIBINPUT_EVENT_TOUCH_MOTION),
    static_cast<int32_t>(LIBINPUT_EVENT_TABLET_TOOL_AXIS),
    static_cast<int32_t>(LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY),
    static_cast<int32_t>(LIBINPUT_EVENT_TABLET_TOOL_TIP),
    static_cast<int32_t>(LIBINPUT_EVENT_JOYSTICK_BUTTON),
    static_cast<int32_t>(LIBINPUT_EVENT_JOYSTICK_AXIS),
    static_cast<int32_t>(LIBINPUT_EVENT_SWITCH_TOGGLE)
};
constexpr int32_t MAX_N_PRESSED_KEYS { 10 };
constexpr int32_t POINTER_MOVEFLAG = { 7 };
}

void EventNormalizeHandler::HandleEvent(libinput_event* event, int64_t frameTime)
{
    CALL_DEBUG_ENTER;

    if (ProcessNullEvent(event, frameTime)) {
        return;
    }

    if (event == nullptr) {
        return;
    }
    DfxHisysevent::GetDispStartTime();
    auto type = libinput_event_get_type(event);

    auto device = libinput_event_get_device(event);
    CHKPV(device);

    if (LIBINPUT_EVENT_DEVICE_ADDED != type && LIBINPUT_EVENT_DEVICE_REMOVED != type) {
        auto deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
        auto enable = INPUT_DEV_MGR->IsInputDeviceEnable(deviceId);
        if (!enable) {
            MMI_HILOGE("The current device has been disabled");
            return;
        }
    }
    std::string name = libinput_device_get_name(device);
    size_t pos = name.find("hand_status_dev");
    if ((pos != std::string::npos) && (type == LIBINPUT_EVENT_MSDP)) {
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
        FingerprintEventHdr->HandleFingerprintEvent(event);
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
        return;
    }
    
    TimeCostChk chk("HandleLibinputEvent", "overtime 1000(us)", MAX_INPUT_EVENT_TIME, type);
    if (type == LIBINPUT_EVENT_TOUCH_CANCEL || type == LIBINPUT_EVENT_TOUCH_FRAME) {
        MMI_HILOGD("This touch event is canceled type:%{public}d", type);
        return;
    }
#ifdef OHOS_BUILD_ENABLE_POINTER
    if ((type == LIBINPUT_EVENT_POINTER_TAP) &&
        (MULTI_FINGERTAP_HDR->GetMultiFingersState() == MulFingersTap::TRIPLE_TAP)) {
        MULTI_FINGERTAP_HDR->SetMultiFingersTapHdrDefault();
        return;
    }
    if ((type < LIBINPUT_EVENT_TOUCHPAD_DOWN) || (type > LIBINPUT_EVENT_TOUCHPAD_MOTION)) {
        auto iter = std::find(ALL_EVENT_TYPES.begin(), ALL_EVENT_TYPES.end(), static_cast<int32_t>(type));
        if (iter != ALL_EVENT_TYPES.end()) {
            MULTI_FINGERTAP_HDR->SetMultiFingersTapHdrDefault();
        }
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    BytraceAdapter::StartHandleInput(static_cast<int32_t>(type));
    switch (type) {
        case LIBINPUT_EVENT_DEVICE_ADDED: {
            OnEventDeviceAdded(event);
            break;
        }
        case LIBINPUT_EVENT_DEVICE_REMOVED: {
            OnEventDeviceRemoved(event);
            break;
        }
        case LIBINPUT_EVENT_KEYBOARD_KEY: {
            HandleKeyboardEvent(event);
            DfxHisysevent::CalcKeyDispTimes();
            break;
        }
        case LIBINPUT_EVENT_POINTER_MOTION:
        case LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE:
        case LIBINPUT_EVENT_POINTER_BUTTON:
        case LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD:
        case LIBINPUT_EVENT_POINTER_SCROLL_FINGER_BEGIN:
        case LIBINPUT_EVENT_POINTER_AXIS:
        case LIBINPUT_EVENT_POINTER_SCROLL_FINGER_END:
        case LIBINPUT_EVENT_POINTER_TAP:
        case LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD: {
            if (g_isSwipeInward) {
                break;
            }
            HandleMouseEvent(event);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
#ifndef OHOS_BUILD_ENABLE_WATCH
        case LIBINPUT_EVENT_TOUCHPAD_DOWN:
        case LIBINPUT_EVENT_TOUCHPAD_UP:
        case LIBINPUT_EVENT_TOUCHPAD_MOTION: {
            HandleTouchPadEvent(event);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
        case LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN:
        case LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE:
        case LIBINPUT_EVENT_GESTURE_SWIPE_END:
        case LIBINPUT_EVENT_GESTURE_PINCH_BEGIN:
        case LIBINPUT_EVENT_GESTURE_PINCH_UPDATE:
        case LIBINPUT_EVENT_GESTURE_PINCH_END: {
            HandleGestureEvent(event);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
        case LIBINPUT_EVENT_TABLET_TOOL_AXIS:
        case LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY:
        case LIBINPUT_EVENT_TABLET_TOOL_TIP: {
            HandleTableToolEvent(event);
            break;
        }
#endif // OHOS_BUILD_ENABLE_WATCH
        case LIBINPUT_EVENT_TOUCH_DOWN:
        case LIBINPUT_EVENT_TOUCH_UP:
        case LIBINPUT_EVENT_TOUCH_MOTION: {
            HandleTouchEvent(event, frameTime);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
#ifdef OHOS_BUILD_ENABLE_JOYSTICK
        case LIBINPUT_EVENT_JOYSTICK_BUTTON: {
            HandleJoystickButtonEvent(event);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
        case LIBINPUT_EVENT_JOYSTICK_AXIS: {
            HandleJoystickAxisEvent(event);
            DfxHisysevent::CalcPointerDispTimes();
            break;
        }
#endif // OHOS_BUILD_ENABLE_JOYSTICK
        case LIBINPUT_EVENT_SWITCH_TOGGLE: {
            HandleSwitchInputEvent(event);
            break;
        }
        default: {
            MMI_HILOGD("This device does not support :%d", type);
            break;
        }
    }
    BytraceAdapter::StopHandleInput();
    DfxHisysevent::ReportDispTimes();
}

bool EventNormalizeHandler::ProcessNullEvent(libinput_event *event, int64_t frameTime)
{
#ifdef OHOS_BUILD_ENABLE_TOUCH
    std::shared_ptr<PointerEvent> pointerEvent = EventResampleHdr->GetPointerEvent();
    if ((event == nullptr) && (pointerEvent != nullptr) && MMISceneBoardJudgement::IsSceneBoardEnabled()
        && MMISceneBoardJudgement::IsResampleEnabled()) {
        int32_t sourceType = pointerEvent->GetSourceType();
        if (sourceType == PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
            HandleTouchEvent(event, frameTime);
        }
        return true;
    }
#endif // OHOS_BUILD_ENABLE_TOUCH
    return false;
}

int32_t EventNormalizeHandler::OnEventDeviceAdded(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    INPUT_DEV_MGR->OnInputDeviceAdded(device);
#if OHOS_BUILD_ENABLE_POINTER
    bool switchFlag = false;
    TOUCH_EVENT_HDR->GetTouchpadDoubleTapAndDragState(switchFlag);
    TOUCH_EVENT_HDR->SetTouchpadDoubleTapAndDragState(switchFlag);
#endif
    KeyMapMgr->ParseDeviceConfigFile(device);
    KeyRepeat->AddDeviceConfig(device);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    KeyEventHdr->ResetKeyEvent(device);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t EventNormalizeHandler::OnEventDeviceRemoved(libinput_event *event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, ERROR_NULL_POINTER);
    KeyMapMgr->RemoveKeyValue(device);
    KeyRepeat->RemoveDeviceConfig(device);
    INPUT_DEV_MGR->OnInputDeviceRemoved(device);
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventNormalizeHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(nextHandler_);
    DfxHisysevent::GetDispStartTime();
    CHKPV(keyEvent);
    EventLogHelper::PrintEventData(keyEvent, MMI_LOG_HEADER);
    UpdateKeyEventHandlerChain(keyEvent);
    if (keyEvent->IsRepeat()) {
        KeyRepeat->SelectAutoRepeat(keyEvent);
        keyEvent->SetRepeat(false);
    }
    DfxHisysevent::CalcKeyDispTimes();
    DfxHisysevent::ReportDispTimes();
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventNormalizeHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(nextHandler_);
    DfxHisysevent::GetDispStartTime();
    CHKPV(pointerEvent);
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_AXIS_END) {
        MMI_HILOGI("MouseEvent Normalization Results, PointerAction:%{public}d, PointerId:%{public}d,"
            "SourceType:%{public}d, ButtonId:%{public}d,"
            "VerticalAxisValue:%{public}lf, HorizontalAxisValue:%{public}lf",
            pointerEvent->GetPointerAction(), pointerEvent->GetPointerId(), pointerEvent->GetSourceType(),
            pointerEvent->GetButtonId(), pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
            pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL));
        PointerEvent::PointerItem item;
        if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), item)) {
            MMI_HILOGE("Get pointer item failed. pointer:%{public}d", pointerEvent->GetPointerId());
            return;
        }
        if (!EventLogHelper::IsBetaVersion()) {
            MMI_HILOGI("MouseEvent Item Normalization Results, IsPressed:%{public}d, Pressure:%{public}f"
                       ", Device:%{public}d",
                static_cast<int32_t>(item.IsPressed()), item.GetPressure(), item.GetDeviceId());
        } else {
            MMI_HILOGI("MouseEvent Item Normalization Results, DownTime:%{public}" PRId64 ", IsPressed:%{public}d,"
                "DisplayX:%{public}d, DisplayY:%{public}d, WindowX:%{public}d, WindowY:%{public}d,"
                "Width:%{public}d, Height:%{public}d, Pressure:%{public}f, MoveFlag:%{public}d, Device:%{public}d",
                item.GetDownTime(), static_cast<int32_t>(item.IsPressed()), item.GetDisplayX(), item.GetDisplayY(),
                item.GetWindowX(), item.GetWindowY(), item.GetWidth(), item.GetHeight(), item.GetPressure(),
                item.GetMoveFlag(), item.GetDeviceId());
        }
    }
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHPAD) {
        WIN_MGR->UpdateTargetPointer(pointerEvent);
    }
    nextHandler_->HandlePointerEvent(pointerEvent);
    DfxHisysevent::CalcPointerDispTimes();
    DfxHisysevent::ReportDispTimes();
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventNormalizeHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(nextHandler_);
    DfxHisysevent::GetDispStartTime();
    CHKPV(pointerEvent);
    WIN_MGR->UpdateTargetPointer(pointerEvent);
    BytraceAdapter::StartTouchEvent(pointerEvent->GetId());
    nextHandler_->HandleTouchEvent(pointerEvent);
    BytraceAdapter::StopTouchEvent();
    DfxHisysevent::CalcPointerDispTimes();
    DfxHisysevent::ReportDispTimes();
}
#endif // OHOS_BUILD_ENABLE_TOUCH

int32_t EventNormalizeHandler::HandleKeyboardEvent(libinput_event* event)
{
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    FingerprintEventHdr->SetPowerAndVolumeKeyState(event);
    if (FingerprintEventHdr->IsFingerprintEvent(event)) {
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
        auto key = KeyEventHdr->GetKeyEvent();
        DfxHisysevent::ReportLaunchAbility(key->GetKeyCode(), key->GetKeyAction(), "Enable Fingerprint");
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
        return FingerprintEventHdr->HandleFingerprintEvent(event);
    }
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
    CHKPR(nextHandler_, ERROR_UNSUPPORT);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    BytraceAdapter::StartPackageEvent("package keyEvent");
    auto keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    CHKPR(event, ERROR_NULL_POINTER);
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    int32_t lastPressedKey = -1;
    if (!pressedKeys.empty()) {
        lastPressedKey = pressedKeys.back();
        MMI_HILOGD("The last repeat button, keyCode:%d", lastPressedKey);
    }
    auto packageResult = KeyEventHdr->Normalize(event, keyEvent);
    EventStatistic::PushEvent(keyEvent);
    LogTracer lt(keyEvent->GetId(), keyEvent->GetEventType(), keyEvent->GetKeyAction());
    if (packageResult == MULTIDEVICE_SAME_EVENT_MARK) {
        MMI_HILOGD("The same event reported by multi_device should be discarded");
        BytraceAdapter::StopPackageEvent();
        return RET_OK;
    }
    if (packageResult != RET_OK) {
        MMI_HILOGE("KeyEvent package failed, ret:%{public}d, errCode:%{public}d", packageResult, KEY_EVENT_PKG_FAIL);
        BytraceAdapter::StopPackageEvent();
        return KEY_EVENT_PKG_FAIL;
    }
    BytraceAdapter::StopPackageEvent();
    BytraceAdapter::StartBytrace(keyEvent);
    EventLogHelper::PrintEventData(keyEvent, MMI_LOG_HEADER);
    auto device = INPUT_DEV_MGR->GetInputDevice(keyEvent->GetDeviceId());
    CHKPR(device, RET_ERR);
    MMI_HILOGI("InputTracking id:%{public}d event created by:%{public}s", keyEvent->GetId(), device->GetName().c_str());
    UpdateKeyEventHandlerChain(keyEvent);
#ifdef SHORTCUT_KEY_RULES_ENABLED
    KEY_SHORTCUT_MGR->UpdateShortcutConsumed(keyEvent);
#endif // SHORTCUT_KEY_RULES_ENABLED
    KeyRepeat->SelectAutoRepeat(keyEvent);
    if (EventLogHelper::IsBetaVersion() && !keyEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
        MMI_HILOGD("keyCode:%{private}d, action:%{public}d", keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
    } else {
        MMI_HILOGD("keyCode:%d, action:%{public}d", keyEvent->GetKeyCode(), keyEvent->GetKeyAction());
    }
#else
    MMI_HILOGW("Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventNormalizeHandler::UpdateKeyEventHandlerChain(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    WIN_MGR->HandleKeyEventWindowId(keyEvent);
    currentHandleKeyCode_ = keyEvent->GetKeyCode();
    int32_t currentShieldMode = KeyEventHdr->GetCurrentShieldMode();
    if (currentShieldMode == SHIELD_MODE::FACTORY_MODE) {
        auto eventDispatchHandler = InputHandler->GetEventDispatchHandler();
        CHKPV(eventDispatchHandler);
        eventDispatchHandler->HandleKeyEvent(keyEvent);
    } else {
        CHKPV(nextHandler_);
        nextHandler_->HandleKeyEvent(keyEvent);
    }
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

int32_t EventNormalizeHandler::HandleMouseEvent(libinput_event* event)
{
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    if (FingerprintEventHdr->IsFingerprintEvent(event)) {
        return FingerprintEventHdr->HandleFingerprintEvent(event);
    }
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
#ifdef OHOS_BUILD_ENABLE_POINTER
    if (CROWN_EVENT_HDR->IsCrownEvent(event)) {
#ifdef OHOS_BUILD_ENABLE_CROWN
        return CROWN_EVENT_HDR->NormalizeRotateEvent(event);
#else
        return RET_ERR;
#endif // OHOS_BUILD_ENABLE_CROWN
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    CHKPR(nextHandler_, ERROR_UNSUPPORT);
#ifdef OHOS_BUILD_ENABLE_POINTER
    BytraceAdapter::StartPackageEvent("package mouseEvent");
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    const auto &keyEvent = KeyEventHdr->GetKeyEvent();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
    if (MouseEventHdr->CheckFilterMouseEvent(event)) {
        MMI_HILOGD("Mouse motion event have been filtered");
        BytraceAdapter::StopPackageEvent();
        return RET_OK;
    }
#endif // OHOS_BUILD_MOUSE_REPORTING_RATE
    if (MouseEventHdr->OnEvent(event) == RET_ERR) {
        MMI_HILOGD("OnEvent is failed");
        BytraceAdapter::StopPackageEvent();
        return RET_ERR;
    }
    auto pointerEvent = MouseEventHdr->GetPointerEvent();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
    for (const int32_t& keyCode : pressedKeys) {
        MMI_HILOGI("Pressed keyCode:%d", keyCode);
    }
    pointerEvent->SetPressedKeys(pressedKeys);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    BytraceAdapter::StopPackageEvent();
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START);
    HandlePalmEvent(event, pointerEvent);
    if (SetOriginPointerId(pointerEvent) != RET_OK) {
        MMI_HILOGE("Failed to set origin pointerId");
        return RET_ERR;
    }
    EventStatistic::PushPointerEvent(pointerEvent);
    nextHandler_->HandlePointerEvent(pointerEvent);
#else
    MMI_HILOGW("Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

void EventNormalizeHandler::HandlePalmEvent(libinput_event* event, std::shared_ptr<PointerEvent> pointerEvent)
{
    auto touchpad = libinput_event_get_touchpad_event(event);
    if (touchpad == nullptr) {
        return;
    }
    int32_t toolType = libinput_event_touchpad_get_tool_type(touchpad);
    if (toolType == MT_TOOL_PALM) {
        MMI_HILOGI("The toolType is MT_TOOL_PALM");
        pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    }
}

bool EventNormalizeHandler::HandleTouchPadTripleTapEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPF(nextHandler_);
#ifndef OHOS_BUILD_ENABLE_WATCH
    if (MULTI_FINGERTAP_HDR->GetMultiFingersState() == MulFingersTap::TRIPLE_TAP) {
        bool threeFingerSwitch = false;
        TOUCH_EVENT_HDR->GetTouchpadThreeFingersTapSwitch(threeFingerSwitch);
        if (!threeFingerSwitch) {
            return true;
        }
        nextHandler_->HandlePointerEvent(pointerEvent);
        MULTI_FINGERTAP_HDR->ClearPointerItems(pointerEvent);
    }
#endif // OHOS_BUILD_ENABLE_WATCH
    return false;
}

#ifndef OHOS_BUILD_ENABLE_WATCH
int32_t EventNormalizeHandler::HandleTouchPadEvent(libinput_event* event)
{
    CHKPR(nextHandler_, ERROR_UNSUPPORT);
#ifdef OHOS_BUILD_ENABLE_POINTER
    CHKPR(event, ERROR_NULL_POINTER);
    auto touchpad = libinput_event_get_touchpad_event(event);
    CHKPR(touchpad, ERROR_NULL_POINTER);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCHPAD_MOTION && TouchPadKnuckleDoubleClickHandle(event)) {
        return RET_OK;
    }
    int32_t seatSlot = libinput_event_touchpad_get_seat_slot(touchpad);
    MULTI_FINGERTAP_HDR->HandleMulFingersTap(touchpad, type);
    auto pointerEvent = TOUCH_EVENT_HDR->OnLibInput(event, TouchEventNormalize::DeviceType::TOUCH_PAD);
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    EventStatistic::PushPointerEvent(pointerEvent);
    if (HandleTouchPadTripleTapEvent(pointerEvent)) {
        return RET_OK;
    }
    buttonIds_.insert(seatSlot);
    if (buttonIds_.size() == FINGER_NUM &&
        (type == LIBINPUT_EVENT_TOUCHPAD_DOWN || type == LIBINPUT_EVENT_TOUCHPAD_UP)) {
        g_isSwipeInward = false;
    }
    if (buttonIds_.size() == SWIPE_INWARD_FINGER_ONE && JudgeIfSwipeInward(pointerEvent, type, event)) {
        nextHandler_->HandlePointerEvent(pointerEvent);
    }
    if (type == LIBINPUT_EVENT_TOUCHPAD_UP) {
        pointerEvent->RemovePointerItem(pointerEvent->GetPointerId());
        MMI_HILOGD("This event is up remove this finger");
        if (pointerEvent->GetPointerIds().empty()) {
            MMI_HILOGD("This event is final up");
            pointerEvent->Reset();
        }
        buttonIds_.erase(seatSlot);
        g_isSwipeInward = false;
    }
    if (buttonIds_.empty()) {
        MULTI_FINGERTAP_HDR->SetMultiFingersTapHdrDefault(false);
    }
    MMI_HILOGD("Button ids count:%{public}d, action:%{public}d",
        static_cast<int32_t>(buttonIds_.size()), pointerEvent->GetPointerAction());
    return RET_OK;
#else
    MMI_HILOGW("Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}

int32_t EventNormalizeHandler::HandleGestureEvent(libinput_event* event)
{
    CHKPR(nextHandler_, ERROR_UNSUPPORT);
#ifdef OHOS_BUILD_ENABLE_POINTER
    CHKPR(event, ERROR_NULL_POINTER);
    auto pointerEvent = TOUCH_EVENT_HDR->OnLibInput(event, TouchEventNormalize::DeviceType::TOUCH_PAD);
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    PointerEventSetPressedKeys(pointerEvent);
    EventStatistic::PushPointerEvent(pointerEvent);
    nextHandler_->HandlePointerEvent(pointerEvent);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_GESTURE_SWIPE_END || type == LIBINPUT_EVENT_GESTURE_PINCH_END) {
        pointerEvent->RemovePointerItem(pointerEvent->GetPointerId());
        MMI_HILOGD("This touch pad event is up remove this finger");
        if (pointerEvent->GetPointerIds().empty()) {
            MMI_HILOGD("This touch pad event is final finger up remove this finger");
            pointerEvent->Reset();
        }
    }
#else
    MMI_HILOGW("Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_WATCH

int32_t EventNormalizeHandler::HandleTouchEvent(libinput_event* event, int64_t frameTime)
{
    CHKPR(nextHandler_, ERROR_UNSUPPORT);
    CHKPR(event, ERROR_NULL_POINTER);
#ifdef OHOS_RSS_CLIENT
    if (libinput_event_get_type(event) == LIBINPUT_EVENT_TOUCH_DOWN) {
        std::unordered_map<std::string, std::string> mapPayload;
        auto begin = std::chrono::high_resolution_clock::now();
        OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(
            OHOS::ResourceSchedule::ResType::RES_TYPE_CLICK_RECOGNIZE,
            OHOS::ResourceSchedule::ResType::ClickEventType::TOUCH_EVENT_DOWN_MMI,
            mapPayload);
        auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - begin).count();
        DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::RS_NOTIFY_TOUCH_EVENT, durationMS);
        mapPayload.clear();
    }
#endif
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    FingerprintEventHdr->SetScreenState(event);
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
#ifdef OHOS_BUILD_ENABLE_TOUCH
    BytraceAdapter::StartPackageEvent("package touchEvent");
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    LogTracer lt;
    auto touch = libinput_event_get_touch_event(event);
    CHKPR(touch, ERROR_NULL_POINTER);
    int32_t moveFlag = libinput_event_touch_get_move_flag(touch);
    if (moveFlag == POINTER_MOVEFLAG) {
        pointerEvent = TOUCH_EVENT_HDR->OnLibInput(event, TouchEventNormalize::DeviceType::REMOTE_CONTROL);
        CHKPR(pointerEvent, ERROR_NULL_POINTER);
    } else {
        pointerEvent = TOUCH_EVENT_HDR->OnLibInput(event, TouchEventNormalize::DeviceType::TOUCH);
        CHKPR(pointerEvent, ERROR_NULL_POINTER);
    }
    if (moveFlag == POINTER_MOVEFLAG && pointerEvent->GetPointerAction() != POINTER_ACTION_MOVE) {
        MMI_HILOGD("Tv Touch event is not Motion");
        return RET_OK;
    }
    lt = LogTracer(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    
#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    if (HandleTouchEventWithFlag(pointerEvent)) {
        MMI_HILOGD("Touch event is filtered with flag");
        return RET_OK;
    }
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
    if (MMISceneBoardJudgement::IsSceneBoardEnabled() && MMISceneBoardJudgement::IsResampleEnabled()) {
        ErrCode status = RET_OK;
        std::shared_ptr<PointerEvent> outputEvent = EventResampleHdr->OnEventConsume(pointerEvent, frameTime, status);
        CHKPR(outputEvent, RET_OK);
        MMI_HILOGD("Output event received, SourceType:%{public}d, PointerAction:%{public}d, status:%{public}d",
            outputEvent->GetSourceType(), outputEvent->GetPointerAction(), status);
        CHKPR(pointerEvent, RET_ERR);
        EndLogTraceId(pointerEvent->GetId());
        pointerEvent = outputEvent;
        lt = LogTracer(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    }
    BytraceAdapter::StopPackageEvent();
    EventStatistic::PushPointerEvent(pointerEvent);
    PointerEventSetPressedKeys(pointerEvent);

    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START);
    if (SetOriginPointerId(pointerEvent) != RET_OK) {
        MMI_HILOGE("Failed to set origin pointerId");
        return RET_ERR;
    }
    if (pointerEvent->GetSourceType() == PointerEvent::SOURCE_TYPE_MOUSE) {
        nextHandler_->HandlePointerEvent(pointerEvent);
    } else {
        nextHandler_->HandleTouchEvent(pointerEvent);
    }
    if ((pointerEvent != nullptr) && (event != nullptr)) {
        ResetTouchUpEvent(pointerEvent, event);
    }
#else
    MMI_HILOGW("Touchscreen device does not support");
#endif // OHOS_BUILD_ENABLE_TOUCH
    return RET_OK;
}

void EventNormalizeHandler::PointerEventSetPressedKeys(std::shared_ptr<PointerEvent> pointerEvent)
{
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    if (KeyEventHdr != nullptr) {
        const auto &keyEvent = KeyEventHdr->GetKeyEvent();
        if (keyEvent != nullptr && pointerEvent != nullptr) {
            std::vector<int32_t> setPressedKeys;
            std::vector<int32_t> pressedKeys = keyEvent->GetPressedKeys();
            if (pressedKeys.size() > MAX_N_PRESSED_KEYS) {
                setPressedKeys.insert(setPressedKeys.begin(), pressedKeys.begin(),
                    pressedKeys.begin() + MAX_N_PRESSED_KEYS);
            } else {
                setPressedKeys = pressedKeys;
            }
            pointerEvent->SetPressedKeys(setPressedKeys);
        }
    }
#endif // OHOS_BUILD_ENABLE_KEYBOARD
}

void EventNormalizeHandler::ResetTouchUpEvent(std::shared_ptr<PointerEvent> pointerEvent,
    struct libinput_event *event)
{
    CHKPV(pointerEvent);
    CHKPV(event);
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_TOUCH_UP) {
        pointerEvent->RemovePointerItem(pointerEvent->GetPointerId());
        MMI_HILOGD("This touch event is up remove this finger");
        if (pointerEvent->GetPointerIds().empty()) {
            MMI_HILOGD("This touch event is final finger up remove this finger");
            pointerEvent->Reset();
        }
    }
}

#ifndef OHOS_BUILD_ENABLE_WATCH
int32_t EventNormalizeHandler::HandleTableToolEvent(libinput_event* event)
{
    CHKPR(nextHandler_, ERROR_UNSUPPORT);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    CHKPR(event, ERROR_NULL_POINTER);
    BytraceAdapter::StartPackageEvent("package penEvent");
    auto pointerEvent = TOUCH_EVENT_HDR->OnLibInput(event, TouchEventNormalize::DeviceType::TABLET_TOOL);
    BytraceAdapter::StopPackageEvent();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START);
    EventStatistic::PushPointerEvent(pointerEvent);
    nextHandler_->HandleTouchEvent(pointerEvent);
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
        pointerEvent->Reset();
    }
#else
    MMI_HILOGW("TableTool device does not support");
#endif // OHOS_BUILD_ENABLE_TOUCH
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_WATCH

#ifdef OHOS_BUILD_ENABLE_JOYSTICK
int32_t EventNormalizeHandler::HandleJoystickButtonEvent(libinput_event *event)
{
    CHKPR(nextHandler_, ERROR_UNSUPPORT);
    CHKPR(event, ERROR_NULL_POINTER);
    BytraceAdapter::StartPackageEvent("package joystick button event");
    auto keyEvent = joystick_.OnButtonEvent(event);
    BytraceAdapter::StopPackageEvent();
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    BytraceAdapter::StartBytrace(keyEvent);
    EventStatistic::PushEvent(keyEvent);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    nextHandler_->HandleKeyEvent(keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    return RET_OK;
}

int32_t EventNormalizeHandler::HandleJoystickAxisEvent(libinput_event *event)
{
    CHKPR(nextHandler_, ERROR_UNSUPPORT);
    CHKPR(event, ERROR_NULL_POINTER);
    BytraceAdapter::StartPackageEvent("package joystick axis event");
    auto pointerEvent = joystick_.OnAxisEvent(event);
    BytraceAdapter::StopPackageEvent();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    PointerEventSetPressedKeys(pointerEvent);
    BytraceAdapter::StartBytrace(pointerEvent, BytraceAdapter::TRACE_START);
    EventStatistic::PushPointerEvent(pointerEvent);
#ifdef OHOS_BUILD_ENABLE_POINTER
    nextHandler_->HandlePointerEvent(pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER
    joystick_.CheckIntention(pointerEvent, [this](std::shared_ptr<KeyEvent> keyEvent) {
        BytraceAdapter::StartBytrace(keyEvent);
        EventStatistic::PushEvent(keyEvent);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        nextHandler_->HandleKeyEvent(keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    });
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_JOYSTICK

int32_t EventNormalizeHandler::HandleSwitchInputEvent(libinput_event* event)
{
    CHKPR(nextHandler_, ERROR_UNSUPPORT);
#ifdef OHOS_BUILD_ENABLE_SWITCH
    CHKPR(event, ERROR_NULL_POINTER);
    struct libinput_event_switch *swev = libinput_event_get_switch_event(event);
    CHKPR(swev, ERROR_NULL_POINTER);

    enum libinput_switch_state state = libinput_event_switch_get_switch_state(swev);
    enum libinput_switch sw = libinput_event_switch_get_switch(swev);
    MMI_HILOGI("The libinput_event_switch type:%{public}d, state:%{public}d", sw, state);
    if (sw == LIBINPUT_SWITCH_PRIVACY && state == LIBINPUT_SWITCH_STATE_OFF) {
        MMI_HILOGD("Privacy switch event ignored");
        return RET_OK;
    }
    auto swEvent = std::make_unique<SwitchEvent>(static_cast<int32_t>(state));
    int32_t switchStatus = static_cast<int32_t>(sw);
    if (switchStatus) {
        RestoreTouchPadStatus();
    }
    swEvent->SetSwitchType(switchStatus);
    EventStatistic::PushEvent(std::move(swEvent));
    nextHandler_->HandleSwitchEvent(std::move(swEvent));
#else
    MMI_HILOGW("Switch device does not support");
#endif // OHOS_BUILD_ENABLE_SWITCH
    return RET_OK;
}

int32_t EventNormalizeHandler::AddHandleTimer(int32_t timeout)
{
    CALL_DEBUG_ENTER;
    timerId_ = TimerMgr->AddTimer(timeout, 1, [this]() {
        timerId_ = -1;
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
        auto keyEvent = KeyEventHdr->GetKeyEvent();
        CHKPV(keyEvent);
        UpdateKeyEventHandlerChain(keyEvent);
        int32_t triggerTime = KeyRepeat->GetIntervalTime(keyEvent->GetDeviceId());
        this->AddHandleTimer(triggerTime);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    });
    return timerId_;
}

#ifdef OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS
int32_t EventNormalizeHandler::SetMoveEventFilters(bool flag)
{
    moveEventFilterFlag_ = flag;

    int32_t ret = PREFERENCES_MGR->SetBoolValue("moveEventFilterFlag", "mouse_settings.xml", moveEventFilterFlag_);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to save moveEventFilterFlag, ret:%{public}d", ret);
    }
    return ret;
}

bool EventNormalizeHandler::HandleTouchEventWithFlag(const std::shared_ptr<PointerEvent> pointerEvent)
{
    if (!moveEventFilterFlag_) {
        return false;
    }
    CHKPF(pointerEvent);
    if (pointerEvent->GetSourceType() != PointerEvent::SOURCE_TYPE_TOUCHSCREEN) {
        return false;
    }
    static bool isFirstMoveEvent = false;
    int32_t action = pointerEvent->GetPointerAction();
    if (action == PointerEvent::POINTER_ACTION_DOWN) {
        isFirstMoveEvent = false;
        lastTouchDownItems_ = pointerEvent->GetAllPointerItems();
    } else if (action == PointerEvent::POINTER_ACTION_MOVE) {
        if (isFirstMoveEvent) {
            return false;
        }
        double offset = CalcTouchOffset(pointerEvent);
        bool isMoveEventFiltered = MMI_LNE(offset, TOUCH_SLOP);
        MMI_HILOGD("Touch move event, offset:%{public}f, isMoveEventFiltered:%{public}s",
            offset, isMoveEventFiltered ? "true" : "false");
        isFirstMoveEvent = !isMoveEventFiltered;
        return isMoveEventFiltered;
    } else if (action == PointerEvent::POINTER_ACTION_UP) {
        lastTouchDownItems_.clear();
    }
    return false;
}

double EventNormalizeHandler::CalcTouchOffset(const std::shared_ptr<PointerEvent> touchMoveEvent)
{
    CHKPR(touchMoveEvent, ERROR_NULL_POINTER);
    auto moveItems = touchMoveEvent->GetAllPointerItems();
    if (moveItems.empty() || lastTouchDownItems_.empty()) {
        MMI_HILOGE("moveItems or lastTouchDownItems_ is empty");
        return 0.f;
    }
    PointerEvent::PointerItem itemMove = moveItems.front();
    PointerEvent::PointerItem itemDown = lastTouchDownItems_.front();
    double offset = sqrt(pow(itemMove.GetDisplayX() - itemDown.GetDisplayX(), SQUARE) +
        pow(itemMove.GetDisplayY() - itemDown.GetDisplayY(), SQUARE));
    auto displayInfo = WIN_MGR->GetPhysicalDisplay(touchMoveEvent->GetTargetDisplayId());
    if (displayInfo != nullptr) {
        double scale = static_cast<double>(displayInfo->dpi) / DENSITY_BASELINE;
        if (!MMI_EQ(static_cast<float>(scale), 0.f)) {
            offset /= scale;
        }
    }
    return offset;
}
#endif // OHOS_BUILD_ENABLE_MOVE_EVENT_FILTERS

int32_t EventNormalizeHandler::SetOriginPointerId(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    pointerItem.SetOriginPointerId(pointerItem.GetPointerId());
    pointerEvent->UpdatePointerItem(pointerId, pointerItem);
    MMI_HILOGD("pointerId:%{public}d, originPointerId:%{public}d",
        pointerId, pointerItem.GetPointerId());
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_SWITCH
void EventNormalizeHandler::RestoreTouchPadStatus()
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_POINTER
    auto ids = INPUT_DEV_MGR->GetTouchPadIds();
    for (auto id : ids) {
        MMI_HILOGI("Restore touchpad, deviceId:%{public}d", id);
        auto mouseEvent = TOUCH_EVENT_HDR->GetPointerEvent(id);
        if (mouseEvent != nullptr) {
            mouseEvent->Reset();
        }
        mouseEvent = MouseEventHdr->GetPointerEvent(id);
        if (mouseEvent != nullptr) {
            mouseEvent->Reset();
        }
    }
#endif // OHOS_BUILD_ENABLE_POINTER
    buttonIds_.clear();
}
#endif // OHOS_BUILD_ENABLE_SWITCH

void EventNormalizeHandler::CancelTwoFingerAxis(libinput_event* event)
{
    CALL_DEBUG_ENTER;
    auto type = libinput_event_get_type(event);
    if (type != LIBINPUT_EVENT_GESTURE_PINCH_BEGIN) {
        MMI_HILOGI("Current event is not expected");
        return;
    }
    bool result = MouseEventHdr->CheckAndPackageAxisEvent(event);
    if (!result) {
        MMI_HILOGI("Check or packet axis event failed");
        return;
    }
    auto pointerEvent = MouseEventHdr->GetPointerEvent();
    CHKPV(pointerEvent);
    nextHandler_->HandlePointerEvent(pointerEvent);
}

void EventNormalizeHandler::TerminateAxis(libinput_event* event)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_POINTER
    auto type = libinput_event_get_type(event);
    if (type == LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD) {
        bool result = MouseEventHdr->CheckAndPackageAxisEvent(event);
        if (!result) {
            return;
        }
        MMI_HILOGI("Terminate axis event");
        auto pointerEvent = MouseEventHdr->GetPointerEvent();
        CHKPV(pointerEvent);
        LogTracer lt(pointerEvent->GetId(), pointerEvent->GetEventType(), pointerEvent->GetPointerAction());
        nextHandler_->HandlePointerEvent(pointerEvent);
    }
#else
    MMI_HILOGW("Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
}

bool EventNormalizeHandler::JudgeIfSwipeInward(std::shared_ptr<PointerEvent> pointerEvent,
    enum libinput_event_type type, libinput_event* event)
{
    static int32_t angleTolerance = 0;
    static int32_t lastDirection = 0;
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    if (g_isSwipeInward == false &&
        type == LIBINPUT_EVENT_TOUCHPAD_DOWN &&
        pointerEvent->GetAllPointerItems().size() == SWIPE_INWARD_FINGER_ONE) {
        auto touchPadDevice = libinput_event_get_device(event);
        // product isolation
        uint32_t touchPadDeviceId = libinput_device_get_id_product(touchPadDevice);
        if (touchPadDeviceId != TABLET_PRODUCT_DEVICE_ID && touchPadDeviceId != BLE_PRODUCT_DEVICE_ID) {
            return g_isSwipeInward;
        }
        // get touchpad physic size
        if (libinput_device_get_size(touchPadDevice, &g_touchPadDeviceWidth, &g_touchPadDeviceHeight)) {
            MMI_HILOGD("judgeIfSwipeInward, get touchPad physic size error");
        }
        // get touchpad max axis size
        g_touchPadDeviceAxisX = libinput_device_get_axis_max(touchPadDevice, USELIB_ABS_MT_POSITION_X);
        g_touchPadDeviceAxisY = libinput_device_get_axis_max(touchPadDevice, USELIB_ABS_MT_POSITION_Y);
        // if down position on edge, start deliver data
        if (pointerEvent->GetAllPointerItems().begin()->GetDisplayX() >=
            g_touchPadDeviceWidth - SWIPE_INWARD_EDGE_X_THRE) {
            lastDirection = -1; // -1 means direction from right to left
            g_isSwipeInward = true;
        } else if (pointerEvent->GetAllPointerItems().begin()->GetDisplayX() <= SWIPE_INWARD_EDGE_X_THRE) {
            lastDirection = 1; // 1 means direction from left to right
            g_isSwipeInward = true;
        }
    }
    // judge
    if (g_isSwipeInward == true) {
        SwipeInwardProcess(pointerEvent, type, event, &angleTolerance, lastDirection);
    }
    return g_isSwipeInward;
}

void EventNormalizeHandler::SwipeInwardProcess(std::shared_ptr<PointerEvent> pointerEvent,
    enum libinput_event_type type, libinput_event* event, int32_t* angleTolerance, int32_t lastDirection)
{
    static int32_t lastPointerX;
    static int32_t lastPointerY;
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGD("judgeIfSwipeInward, Can't find pointerItem");
        g_isSwipeInward = false;
        return;
    }
    switch (static_cast<int32_t>(type)) {
        case static_cast<int32_t>(LIBINPUT_EVENT_TOUCHPAD_DOWN):
            pointerItem.SetDisplayX(g_touchPadDeviceAxisX);
            pointerItem.SetDisplayY(g_touchPadDeviceAxisY);
            *angleTolerance = SWIPE_INWARD_ANGLE_TOLERANCE;
            return;
        case static_cast<int32_t>(LIBINPUT_EVENT_TOUCHPAD_MOTION): {
            auto touchpad = libinput_event_get_touchpad_event(event);
            pointerItem.SetDisplayX(static_cast<int32_t>(
                (libinput_event_touchpad_get_x(touchpad) / g_touchPadDeviceWidth) * g_touchPadDeviceAxisX));
            pointerItem.SetDisplayY(static_cast<int32_t>(
                (libinput_event_touchpad_get_y(touchpad) / g_touchPadDeviceHeight) * g_touchPadDeviceAxisY));
            break;
        }
        case static_cast<int32_t>(LIBINPUT_EVENT_TOUCHPAD_UP):
            lastPointerX = 0;
            return;
        default:
            return;
    }
    // angle and direction judge
    if ((std::abs(pointerItem.GetDisplayX() - lastPointerX) * SWIPE_INWARD_ANGLE_JUDGE <
        std::abs(pointerItem.GetDisplayY() - lastPointerY) ||
        (pointerItem.GetDisplayX() - lastPointerX) * lastDirection < 0) && lastPointerX) {
        --(*angleTolerance); // angle judge have more weights than direction judge
        --(*angleTolerance);
    }
    lastPointerX = pointerItem.GetDisplayX();
    lastPointerY = pointerItem.GetDisplayY();
}

bool EventNormalizeHandler::TouchPadKnuckleDoubleClickHandle(libinput_event* event)
{
    CHKPF(event);
    CHKPF(nextHandler_);
    auto touchpadEvent = libinput_event_get_touchpad_event(event);
    CHKPF(touchpadEvent);
    double value = libinput_event_touchpad_get_pressure(touchpadEvent);
    std::shared_ptr<MMI::KeyEvent> keyEvent = KeyEvent::Create();
    CHKPF(keyEvent);
    if (std::fabs(SINGLE_KNUCKLE_ABS_PRESSURE_VALUE - value) <= std::numeric_limits<double>::epsilon()) {
        keyEvent->SetKeyAction(KNUCKLE_1F_DOUBLE_CLICK);
        MMI_HILOGI("Current is touchPad single knuckle double click action");
        nextHandler_->HandleKeyEvent(keyEvent);
        return true;
    }
    if (value == DOUBLE_KNUCKLE_ABS_PRESSURE_VALUE) {
        keyEvent->SetKeyAction(KNUCKLE_2F_DOUBLE_CLICK);
        MMI_HILOGI("Current is touchPad double knuckle double click action");
        nextHandler_->HandleKeyEvent(keyEvent);
        return true;
    }
    return false;
}
} // namespace MMI
} // namespace OHOS
