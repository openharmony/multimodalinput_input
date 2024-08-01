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

#include "fingerprint_event_processor.h"

#include "event_log_helper.h"
#include "input_event_handler.h"
#include "pointer_event.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "FingerprintEventProcessor"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
namespace {
constexpr int32_t POWER_KEY_INIT { 0 };
constexpr int32_t POWER_KEY_DOWN { 1 };
constexpr int32_t POWER_KEY_UP { 2 };
constexpr int32_t POWER_KEY_UP_TIME { 1000 }; // 1000ms
}
FingerprintEventProcessor::FingerprintEventProcessor()
{}

FingerprintEventProcessor::~FingerprintEventProcessor()
{}

bool FingerprintEventProcessor::IsFingerprintEvent(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, false);
    auto device = libinput_event_get_device(event);
    CHKPR(device, false);
    std::string name = libinput_device_get_name(device);
    if (name != FINGERPRINT_SOURCE_KEY && name != FINGERPRINT_SOURCE_POINT) {
        MMI_HILOGD("Not FingerprintEvent");
        return false;
    }
    if (name == FINGERPRINT_SOURCE_KEY) {
        struct libinput_event_keyboard* keyBoard = libinput_event_get_keyboard_event(event);
        CHKPR(keyBoard, false);
        auto key = libinput_event_keyboard_get_key(keyBoard);
        if (key != FINGERPRINT_CODE_DOWN && key != FINGERPRINT_CODE_UP
            && key != FINGERPRINT_CODE_CLICK && key != FINGERPRINT_CODE_RETOUCH) {
            MMI_HILOGD("Not FingerprintEvent event");
            return false;
        }
    }
    return true;
}
void FingerprintEventProcessor::SetPowerKeyState(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    CHKPV(event);
    auto device = libinput_event_get_device(event);
    CHKPV(device);
    auto data = libinput_event_get_keyboard_event(event);
    CHKPV(data);
    int32_t keyCode = static_cast<int32_t>(libinput_event_keyboard_get_key(data));
    if (keyCode != KEY_POWER) {
        MMI_HILOGD("current keycode is not power, return");
        return;
    }
    int32_t keyAction = (libinput_event_keyboard_get_key_state(data) == 0) ?
        (KeyEvent::KEY_ACTION_UP) : (KeyEvent::KEY_ACTION_DOWN);
    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        powerKeyState_ = POWER_KEY_DOWN;
    } else {
        powerKeyState_ = POWER_KEY_UP;
        lastUpTime_ = std::chrono::steady_clock::now();
    }
}

int32_t FingerprintEventProcessor::HandleFingerprintEvent(struct libinput_event* event)
{
    CALL_DEBUG_ENTER;
    if (powerKeyState_ == POWER_KEY_DOWN) {
        MMI_HILOGD("Dont report because current state is powerkey down");
        return 0;
    } else if (powerKeyState_ == POWER_KEY_UP) {
        auto currentTime = std::chrono::steady_clock::now();
        auto duration = currentTime - lastUpTime_;
        auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        if (durationMs < POWER_KEY_UP_TIME) {
            MMI_HILOGD("Dont report because time diff < 1s");
            return 0;
        } else {
            powerKeyState_ = POWER_KEY_INIT;
        }
    }
    CHKPR(event, ERROR_NULL_POINTER);
    auto device = libinput_event_get_device(event);
    CHKPR(device, PARAM_INPUT_INVALID);
    std::string name = libinput_device_get_name(device);
    if (name == FINGERPRINT_SOURCE_KEY) {
        return AnalyseKeyEvent(event);
    } else if (name == FINGERPRINT_SOURCE_POINT) {
        return AnalysePointEvent(event);
    } else {
        MMI_HILOGI("Unknown input device name:%{public}s", name.c_str());
        return PARAM_INPUT_INVALID;
    }
}

int32_t FingerprintEventProcessor::AnalyseKeyEvent(struct libinput_event *event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);
    struct libinput_event_keyboard* keyEvent = libinput_event_get_keyboard_event(event);
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    auto key = libinput_event_keyboard_get_key(keyEvent);
    enum libinput_key_state state = libinput_event_keyboard_get_key_state(keyEvent);
    if (state == LIBINPUT_KEY_STATE_PRESSED) {
        MMI_HILOGI("Dont analyse the press status for %{public}d", key);
        return ERR_OK;
    }
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    switch (key) {
        case FINGERPRINT_CODE_DOWN: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_DOWN);
            break;
        }
        case FINGERPRINT_CODE_UP: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_UP);
            break;
        }
        case FINGERPRINT_CODE_RETOUCH: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_RETOUCH);
            break;
        }
        case FINGERPRINT_CODE_CLICK: {
            pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_CLICK);
            break;
        }
        default:
            MMI_HILOGW("Unknown key event:%{public}d", key);
            return UNKNOWN_EVENT;
    }
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerId(0);
    EventLogHelper::PrintEventData(pointerEvent, MMI_LOG_HEADER);
    MMI_HILOGD("Fingerprint key:%{public}d", pointerEvent->GetPointerAction());
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && defined(OHOS_BUILD_ENABLE_MONITOR)
    auto eventMonitorHandler_ = InputHandler->GetMonitorHandler();
    if (eventMonitorHandler_ != nullptr) {
        eventMonitorHandler_->OnHandleEvent(pointerEvent);
    }
#endif // (OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH) && OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}

int32_t FingerprintEventProcessor::AnalysePointEvent(libinput_event * event)
{
    CALL_DEBUG_ENTER;
    struct libinput_event_pointer* rawPointerEvent = libinput_event_get_pointer_event(event);
    CHKPR(rawPointerEvent, ERROR_NULL_POINTER);
    double ux = libinput_event_pointer_get_dx_unaccelerated(rawPointerEvent);
    double uy = libinput_event_pointer_get_dy_unaccelerated(rawPointerEvent);
    auto pointerEvent = PointerEvent::Create();
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    int64_t time = GetSysClockTime();
    pointerEvent->SetActionTime(time);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_FINGERPRINT_SLIDE);
    pointerEvent->SetFingerprintDistanceX(ux);
    pointerEvent->SetFingerprintDistanceY(uy);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->SetPointerId(0);
    EventLogHelper::PrintEventData(pointerEvent, MMI_LOG_HEADER);
    MMI_HILOGD("Fingerprint key:%{public}d, ux:%f, uy:%f", pointerEvent->GetPointerAction(), ux, uy);
#if (defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)) && defined(OHOS_BUILD_ENABLE_MONITOR)
    auto eventMonitorHandler_ = InputHandler->GetMonitorHandler();
    if (eventMonitorHandler_ != nullptr) {
        eventMonitorHandler_->OnHandleEvent(pointerEvent);
    }
#endif // (OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH) && OHOS_BUILD_ENABLE_MONITOR
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
} // namespace MMI
} // namespace OHOS
