/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "libinput_adapter.h"

#include <regex>

#include "param_wrapper.h"
#include "property_reader.h"
#include "input_device_manager.h"
#include "input_windows_manager.h"
#include "key_event_normalize.h"
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
#include "key_event_value_transformation.h"
#include "timer_manager.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "parameters.h"
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
#include "multimodal_input_plugin_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LibinputAdapter"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t WAIT_TIME_FOR_INPUT { 10 };
constexpr int32_t MAX_RETRY_COUNT { 5 };
constexpr int32_t MIN_RIGHT_BTN_AREA_PERCENT { 0 };
constexpr int32_t MAX_RIGHT_BTN_AREA_PERCENT { 100 };
constexpr int32_t INVALID_RIGHT_BTN_AREA { -1 };
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
constexpr uint32_t VKEY_TP_LB_ID { 272 };
constexpr uint32_t VKEY_TP_SEAT_BTN_COUNT_NONE { 0 };
constexpr uint32_t KEY_CAPSLOCK { 58 };
constexpr uint32_t LIBINPUT_KEY_VOLUME_DOWN { 114 };
constexpr uint32_t LIBINPUT_KEY_VOLUME_UP { 115 };
constexpr uint32_t LIBINPUT_KEY_POWER { 116 };
constexpr uint32_t LIBINPUT_KEY_FN { 240 };
constexpr uint32_t VKEY_PINCH_FIRST_FINGER_ID { 0 };
constexpr uint32_t VKEY_PINCH_SECOND_FINGER_ID { 1 };
constexpr float VKEY_RAW_COORDINATE_RATIO { 8.0 };
constexpr uint32_t VKEY_PINCH_CURSOR_FAKE_DX { 1 };
enum class VKeyboardTouchEventType : int32_t {
    TOUCH_DOWN = 0,
    TOUCH_UP = 1,
    TOUCH_MOVE = 2,
    TOUCH_FRAME = 3,
};
constexpr int32_t WAIT_TIME_MS_STAP { 180 };  // milliseconds touch up delay for Single TAP
constexpr int32_t WAIT_TIME_MS_DTAP { 60 };  // milliseconds touch up delay for Double TAP
constexpr int32_t EXPIRED_TIMER_ID { -1 };
#else // OHOS_BUILD_ENABLE_VKEYBOARD
constexpr uint32_t KEY_CAPSLOCK { 58 };
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

void HiLogFunc(struct libinput* input, libinput_log_priority priority, const char* fmt, va_list args)
{
    CHKPV(input);
    CHKPV(fmt);
    char buffer[256] = {};
    if (vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, fmt, args) == -1) {
        MMI_HILOGE("Call vsnprintf_s failed");
        va_end(args);
        return;
    }
    if (strstr(buffer, "LOG_LEVEL_I") != nullptr) {
        MMI_HILOGI("PrintLog_Info:%{public}s", buffer);
    } else if (strstr(buffer, "LOG_LEVEL_D") != nullptr) {
        MMI_HILOGD("PrintLog_Info:%{public}s", buffer);
    } else if (strstr(buffer, "LOG_LEVEL_E") != nullptr) {
        MMI_HILOGE("PrintLog_Info:%{public}s", buffer);
    } else {
        MMI_HILOGD("PrintLog_Info:%{public}s", buffer);
    }
    va_end(args);
}
} // namespace

LibinputAdapter::~LibinputAdapter()
{
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    if (TimerMgr->IsExist(vkbTimerId_)) {
        TimerMgr->RemoveTimer(vkbTimerId_);
        SafeDestroyVKeyboardDelayedEvent();
    }
    if (TimerMgr->IsExist(vtpTimerId_)) {
        TimerMgr->RemoveTimer(vtpTimerId_);
        SafeDestroyVTrackPadDelayedEvent();
    }
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    MMI_HILOGI("~LibinputAdapter");
}

int32_t LibinputAdapter::DeviceLedUpdate(struct libinput_device *device, int32_t funcKey, bool enable)
{
    CHKPR(device, RET_ERR);
    return libinput_set_led_state(device, funcKey, enable);
}

void LibinputAdapter::InitRightButtonAreaConfig()
{
    CHKPV(input_);

    int32_t height_percent = OHOS::system::GetIntParameter("const.multimodalinput.rightclick_y_percentage",
                                                           INVALID_RIGHT_BTN_AREA);
    if ((height_percent <= MIN_RIGHT_BTN_AREA_PERCENT) || (height_percent > MAX_RIGHT_BTN_AREA_PERCENT)) {
        MMI_HILOGE("Right button area height percent param is invalid");
        return;
    }

    int32_t width_percent = OHOS::system::GetIntParameter("const.multimodalinput.rightclick_x_percentage",
                                                          INVALID_RIGHT_BTN_AREA);
    if ((width_percent <= MIN_RIGHT_BTN_AREA_PERCENT) || (width_percent > MAX_RIGHT_BTN_AREA_PERCENT)) {
        MMI_HILOGE("Right button area width percent param is invalid");
        return;
    }

    auto status = libinput_config_rightbutton_area(input_, height_percent, width_percent);
    if (status != LIBINPUT_CONFIG_STATUS_SUCCESS) {
        MMI_HILOGE("Config the touchpad right button area failed");
    }
}

constexpr static libinput_interface LIBINPUT_INTERFACE = {
    .open_restricted = [](const char *path, int32_t flags, void *user_data)->int32_t {
        if (path == nullptr) {
            MMI_HILOGWK("Input device path is nullptr");
            return RET_ERR;
        }
        char realPath[PATH_MAX] = {};
        if (realpath(path, realPath) == nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_INPUT));
            MMI_HILOGWK("The error path is %{private}s", path);
            return RET_ERR;
        }
        int32_t fd = 0;
        for (int32_t i = 0; i < MAX_RETRY_COUNT; i++) {
            fd = open(realPath, flags);
            if (fd >= 0) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_INPUT));
        }
        int32_t errNo = errno;
        std::regex re("(\\d+)");
        std::string str_path(path);
        std::smatch match;
        int32_t id;
        bool isPath = std::regex_search(str_path, match, re);
        if (!isPath) {
            id = -1;
        } else {
            id = std::stoi(match[0]);
        }
        MMI_HILOGWK("Libinput .open_restricted id:%{public}d, fd:%{public}d, errno:%{public}d", id, fd, errNo);
        return fd < 0 ? RET_ERR : fd;
    },
    .close_restricted = [](int32_t fd, void *user_data)
    {
        if (fd < 0) {
            return;
        }
        MMI_HILOGI("Libinput .close_restricted fd:%{public}d", fd);
        close(fd);
    },
};

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
class BootStatusReceiver : public EventFwk::CommonEventSubscriber {
public:
    explicit BootStatusReceiver(const OHOS::EventFwk::CommonEventSubscribeInfo& subscribeInfo)
        : OHOS::EventFwk::CommonEventSubscriber(subscribeInfo)
    {
    }

    virtual ~BootStatusReceiver() = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &eventData)
    {
        LibinputAdapter::SetBootCompleted();
        std::string action = eventData.GetWant().GetAction();
        if (action.empty()) {
            MMI_HILOGE("The action is empty");
            return;
        }
        MMI_HILOGI("Received boot status:%{public}s", action.c_str());
    }
};

std::atomic_bool LibinputAdapter::isBootCompleted_ = false;

void LibinputAdapter::SetBootCompleted()
{
    isBootCompleted_ = true;
}

void LibinputAdapter::RegisterBootStatusReceiver()
{
    if (hasInitSubscriber_) {
        MMI_HILOGE("Current common event has subscribered");
        return;
    }
    MMI_HILOGI("Subscribe Boot Events");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
    EventFwk::CommonEventSubscribeInfo commonEventSubscribeInfo(matchingSkills);
    hasInitSubscriber_ = OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(
        std::make_shared<BootStatusReceiver>(commonEventSubscribeInfo));
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

bool LibinputAdapter::Init(FunInputEvent funInputEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(funInputEvent);

    auto callback = [funInputEvent](libinput_event *event, int64_t frameTime) {
        funInputEvent(static_cast<void *>(event), frameTime);
    };
    auto manager = InputPluginManager::GetInstance();
    if (manager != nullptr) {
        manager->PluginAssignmentCallBack(callback, InputPluginStage::INPUT_BEFORE_LIBINPUT_ADAPTER_ON_EVENT);
    }
    funInputEvent_ = [manager, callback](void *event, int64_t frameTime) {
        if (manager != nullptr) {
            int32_t result = manager->HandleEvent(static_cast<libinput_event *>(event),
                frameTime,
                InputPluginStage::INPUT_BEFORE_LIBINPUT_ADAPTER_ON_EVENT);
            if (result != RET_NOTDO) {
                return;
            }
        }
        callback(static_cast<libinput_event *>(event), frameTime);
    };
    
    input_ = libinput_path_create_context(&LIBINPUT_INTERFACE, nullptr);
    CHKPF(input_);
    libinput_log_set_handler(input_, &HiLogFunc);
    fd_ = libinput_get_fd(input_);
    if (fd_ < 0) {
        libinput_unref(input_);
        fd_ = -1;
        MMI_HILOGE("The fd_ is less than 0");
        return false;
    }
    InitRightButtonAreaConfig();
    return hotplugDetector_.Init([this](std::string path) { OnDeviceAdded(std::move(path)); },
        [this](std::string path) { OnDeviceRemoved(std::move(path)); });
}

void LibinputAdapter::EventDispatch(int32_t fd)
{
    CALL_DEBUG_ENTER;
    if (fd == fd_) {
        MMI_HILOGD("Start to libinput_dispatch");
        if (libinput_dispatch(input_) != 0) {
            MMI_HILOGE("Failed to dispatch libinput");
            return;
        }
        OnEventHandler();
        MMI_HILOGD("End to OnEventHandler");
    } else if (fd == hotplugDetector_.GetFd()) {
        hotplugDetector_.OnEvent();
    } else {
        MMI_HILOGE("EventDispatch() called with unknown fd:%{public}d", fd);
    }
}

void LibinputAdapter::Stop()
{
    CALL_DEBUG_ENTER;
    hotplugDetector_.Stop();
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    if (input_ != nullptr) {
        libinput_unref(input_);
        input_ = nullptr;
    }
}

void LibinputAdapter::ProcessPendingEvents()
{
    OnEventHandler();
}

void LibinputAdapter::InitVKeyboard(HandleTouchPoint handleTouchPoint,
    HardwareKeyEventDetected hardwareKeyEventDetected,
    GetKeyboardActivationState getKeyboardActivationState,
    IsFloatingKeyboard isFloatingKeyboard,
    IsVKeyboardShown isVKeyboardShown,
    GetLibinputEventForVKeyboard getLibinputEventForVKeyboard,
    GetLibinputEventForVTrackpad getLibinputEventForVTrackpad,
    ResetVTrackpadState resetVTrackpadState,
    StopVTrackpadTimer stopVTrackpadTimer)
{
    handleTouchPoint_ = handleTouchPoint;
    hardwareKeyEventDetected_ = hardwareKeyEventDetected;
    getKeyboardActivationState_ = getKeyboardActivationState;
    isFloatingKeyboard_ = isFloatingKeyboard;
    isVKeyboardShown_ = isVKeyboardShown;
    getLibinputEventForVKeyboard_ = getLibinputEventForVKeyboard;
    getLibinputEventForVTrackpad_ = getLibinputEventForVTrackpad;
    resetVTrackpadState_ = resetVTrackpadState;
    stopVTrackpadTimer_ = stopVTrackpadTimer;
    // init touch device Id.
    deviceId = -1;
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
void LibinputAdapter::DelayInjectKeyEventCallback()
{
    if (funInputEvent_ == nullptr) {
        MMI_HILOGW("inject function funInputEvent_ is null");
        SafeDestroyVKeyboardDelayedEvent();
        return;
    }
    int64_t frameTime = GetSysClockTime();
    std::lock_guard<std::mutex> guard(vtrDelayedMutex_);
    if (vkbDelayedKeyEvent_ != nullptr) {
        funInputEvent_(vkbDelayedKeyEvent_, frameTime);
        free(vkbDelayedKeyEvent_);
        vkbDelayedKeyEvent_ = nullptr;
    }
    vkbTimerId_ = EXPIRED_TIMER_ID;
}

libinput_event_touch* LibinputAdapter::SafeGetVTrackPadTouchEvent()
{
    std::lock_guard<std::mutex> guard(vtrDelayedMutex_);
    CHKPP(vtpDelayedEvent_);
    return libinput_event_get_touch_event(vtpDelayedEvent_);
}

void LibinputAdapter::SafeDestroyVKeyboardDelayedEvent()
{
    std::lock_guard<std::mutex> guard(vtrDelayedMutex_);
    vkbTimerId_ = EXPIRED_TIMER_ID;
    CHKPV(vkbDelayedKeyEvent_);
    free(vkbDelayedKeyEvent_);
    vkbDelayedKeyEvent_ = nullptr;
}

void LibinputAdapter::SafeDestroyVTrackPadDelayedEvent()
{
    std::lock_guard<std::mutex> guard(vtrDelayedMutex_);
    vtpTimerId_ = EXPIRED_TIMER_ID;
    stopVTrackpadTimer_();
    CHKPV(vtpDelayedEvent_);
    libinput_event_destroy(vtpDelayedEvent_);
    vtpDelayedEvent_ = nullptr;
}

// return true if timer has started successfully.
bool LibinputAdapter::CreateVKeyboardDelayTimer(int32_t delayMs, libinput_event *keyEvent)
{
    if (keyEvent == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> guard(vtrDelayedMutex_);
    if (vkbDelayedKeyEvent_ != nullptr) {
        MMI_HILOGI("A delayed event is pending, skip delay msg, Delay=%{public}d", delayMs);
        return false;
    }
    vkbDelayedKeyEvent_ = keyEvent;
    StartVKeyboardDelayTimer(delayMs);
    MMI_HILOGI("Create the delayed event, Delay=%{public}d, timer Id=%{public}d", vkbTimerId_, delayMs);
    return true;
}

void LibinputAdapter::StartVKeyboardDelayTimer(int32_t delayMs)
{
    vkbTimerId_ = TimerMgr->AddTimer(delayMs, 1, [this]() {
        DelayInjectKeyEventCallback();
    }, "LibinputAdapter-StartVKeyboardDelayTimer");
}

bool LibinputAdapter::GetIsCaptureMode()
{
    bool isCaptureMode = false;
    bool isFloating = (isFloatingKeyboard_ != nullptr) ? isFloatingKeyboard_() : false;

    InputWindowsManager* inputWindowsManager = static_cast<InputWindowsManager *>(WIN_MGR.get());
    if (inputWindowsManager == nullptr) {
        return false;
    }

    isCaptureMode = inputWindowsManager->IsCaptureMode() && isFloating;
    MMI_HILOGD("isCaptureMode=%{public}d", isCaptureMode);
    return isCaptureMode;
}

void LibinputAdapter::HandleVFullKeyboardMessages(
    libinput_event *event, int64_t frameTime, libinput_event_type eventType, libinput_event_touch *touch)
{
    // delay the event destroy.
    bool delayvtpDestroy = false;

    if (getLibinputEventForVKeyboard_ == nullptr || getLibinputEventForVTrackpad_ == nullptr) {
        return;
    }
    // handle trackpad messages.
    while (true) {
        std::vector<libinput_event*> events;
        VTrackpadEventType eventType = (VTrackpadEventType)getLibinputEventForVTrackpad_(touch, events);
        if (eventType == VTrackpadEventType::NoTrackpadEvent) {
            break;
        }

        HandleVTrackpadMessage(eventType, events, frameTime, touch, event, delayvtpDestroy);
    }

    // handle keyboard messages.
    while (true) {
        int32_t delayMs(0);
        std::vector<libinput_event*> keyEvents;
        VKeyboardEventType eventType = (VKeyboardEventType)getLibinputEventForVKeyboard_(touch, delayMs, keyEvents);
        if (eventType == VKeyboardEventType::NoKeyboardEvent ||
            (keyEvents.empty() && eventType != VKeyboardEventType::HideCursor)) {
            break;
        }

         // if need to delay, not injecting but store them. Limit to up event.
        if (delayMs > 0 && eventType == VKeyboardEventType::StopLongPress &&
            CreateVKeyboardDelayTimer(delayMs, keyEvents.front())) {
            // could skip the handling now, create the delayed events.
            continue;
        }
        HandleVKeyboardMessage(eventType, keyEvents, frameTime);
    }

    if (eventType == LIBINPUT_EVENT_TOUCH_FRAME) {
        // still let frame info go through.
        funInputEvent_(event, frameTime);
    }
    if (!delayvtpDestroy) {
        libinput_event_destroy(event);
    }
}

void LibinputAdapter::HandleVKeyboardMessage(VKeyboardEventType eventType,
                                             std::vector<libinput_event*> &keyboardEvents, int64_t frameTime)
{
    bool newCapsLockState = false;
    bool libinputCapsLockOn = false;
    std::shared_ptr<KeyEvent> keyEvent = KeyEventHdr->GetKeyEvent();
    if (!keyboardEvents.empty()) {
        // check current caps state.
        auto device = libinput_event_get_device(keyboardEvents.front());
        if (keyEvent != nullptr && device != nullptr) {
            newCapsLockState = keyEvent->GetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY);
            libinputCapsLockOn =
                static_cast<bool>(libinput_get_funckey_state(device, MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY));
        } else {
            MMI_HILOGW("Failed to sync virtual keyboard's Caps state given nullptr of keyEvent/device.");
        }
    }
    switch (eventType) {
        case VKeyboardEventType::StopLongPress:
            [[fallthrough]];
        case VKeyboardEventType::NormalKeyboardEvent: {
            for (auto event : keyboardEvents) {
                CHKPC(event);
                funInputEvent_(event, frameTime);
                free(event);
            }
            keyboardEvents.clear();
            break;
        }
        case VKeyboardEventType::UpdateCaps: {
            for (auto event : keyboardEvents) {
                CHKPC(event);
                funInputEvent_(event, frameTime);
                free(event);
            }
            keyboardEvents.clear();
            newCapsLockState = !newCapsLockState;
            if (keyEvent != nullptr) {
                keyEvent->SetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY, newCapsLockState);
            }
            MultiKeyboardSetLedState(newCapsLockState);
            break;
        }
        case VKeyboardEventType::HideCursor: {
            HideMouseCursorTemporary();
            break;
        }
        default:
            break;
    }
    if (libinputCapsLockOn != newCapsLockState) {
        // if a mismatch is found, sync it now.
        libinput_toggle_caps_key();
    }
}

void LibinputAdapter::HandleVTrackpadMessage(VTrackpadEventType eventType, std::vector<libinput_event*> &events,
                                             int64_t frameTime, libinput_event_touch *touch,
                                             libinput_event *event, bool& delayvtpDestroy)
{
    if (eventType == VTrackpadEventType::NoTrackpadEvent) {
        return;
    }

    for (auto event : events) {
        libinput_event_type injectEventType = libinput_event_get_type(event);
        funInputEvent_(event, frameTime);
        free(event);
        event = nullptr;

        if (injectEventType == libinput_event_type::LIBINPUT_EVENT_GESTURE_PINCH_BEGIN) {
            InjectEventForTwoFingerOnTouchpad(touch, libinput_event_type::LIBINPUT_EVENT_TOUCHPAD_DOWN,
                                              frameTime);
        } else if (injectEventType == libinput_event_type::LIBINPUT_EVENT_GESTURE_PINCH_UPDATE) {
            InjectEventForTwoFingerOnTouchpad(touch, libinput_event_type::LIBINPUT_EVENT_TOUCHPAD_MOTION,
                                              frameTime);
        } else if (injectEventType == libinput_event_type::LIBINPUT_EVENT_GESTURE_PINCH_END) {
            if (IsCursorInCastWindow()) {
                InjectEventForCastWindow(touch);
            } else {
                InjectEventForTwoFingerOnTouchpad(touch, libinput_event_type::LIBINPUT_EVENT_TOUCHPAD_UP,
                                                  frameTime);
            }
        }
    }
    events.clear();
    if (eventType == VTrackpadEventType::SingleTap) {
        std::lock_guard<std::mutex> guard(vtrDelayedMutex_);
        delayvtpDestroy = true;
        vtpDelayedEvent_ = event;
        vtpTimerId_ = TimerMgr->AddTimer(WAIT_TIME_MS_STAP, 1, [this]() { DelayInjectReleaseCallback(); });
        MMI_HILOGI("SINGLE_TAP: delay, delayedtime=%{private}d, timer id=%{public}d", WAIT_TIME_MS_STAP, vtpTimerId_);
    } else if (eventType == VTrackpadEventType::DoubleTap) {
        std::lock_guard<std::mutex> guard(vtrDelayedMutex_);
        delayvtpDestroy = true;
        vtpDelayedEvent_ = event;
        vtpTimerId_ = TimerMgr->AddTimer(WAIT_TIME_MS_DTAP, 1, [this]() { DelayInjectPressReleaseCallback(); });
        MMI_HILOGI("DOUBLE_TAP: delay, delayedtime=%{private}d, timer id=%{public}d", WAIT_TIME_MS_DTAP, vtpTimerId_);
    } else if (eventType == VTrackpadEventType::RemoveTimer) {
        MMI_HILOGI("Remove timer, id=%{public}d", vtpTimerId_);
        TimerMgr->RemoveTimer(vtpTimerId_);
        SafeDestroyVTrackPadDelayedEvent();
    }
}

void LibinputAdapter::DelayInjectPressReleaseCallback()
{
    libinput_event_touch *touch = SafeGetVTrackPadTouchEvent();
    if (touch == nullptr || funInputEvent_ == nullptr) {
        SafeDestroyVTrackPadDelayedEvent();
        return;
    }

    int64_t frameTime = GetSysClockTime();
    event_pointer pDownEvent;
    pDownEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_TAP;
    pDownEvent.button = VKEY_TP_LB_ID;
    pDownEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_NONE;
    pDownEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_PRESSED;
    libinput_event_pointer *lpDownEvent = libinput_create_pointer_event(touch, pDownEvent);
    if (lpDownEvent != nullptr) {
        funInputEvent_((libinput_event *)lpDownEvent, frameTime);
        free(lpDownEvent);
        lpDownEvent = nullptr;
        MMI_HILOGI("Virtual TrackPad send: LIBINPUT_EVENT_POINTER_TAP PRESSED");
    }
    event_pointer pUpEvent;
    pUpEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_TAP;
    pUpEvent.button = VKEY_TP_LB_ID;
    pUpEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_NONE;
    pUpEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_RELEASED;
    libinput_event_pointer *lpUpEvent = libinput_create_pointer_event(touch, pUpEvent);
    if (lpUpEvent != nullptr) {
        funInputEvent_((libinput_event *)lpUpEvent, frameTime);
        free(lpUpEvent);
        lpUpEvent = nullptr;
        MMI_HILOGI("Virtual TrackPad send: LIBINPUT_EVENT_POINTER_TAP RELEASED");
    }
    resetVTrackpadState_();
    SafeDestroyVTrackPadDelayedEvent();
}

void LibinputAdapter::DelayInjectReleaseCallback()
{
    libinput_event_touch *touch = SafeGetVTrackPadTouchEvent();
    if (touch == nullptr || funInputEvent_ == nullptr) {
        SafeDestroyVTrackPadDelayedEvent();
        return;
    }
    int64_t frameTime = GetSysClockTime();
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_TAP;
    pEvent.button = VKEY_TP_LB_ID;
    pEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_NONE;
    pEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_RELEASED;
    libinput_event_pointer *lpEvent = libinput_create_pointer_event(touch, pEvent);
    if (lpEvent != nullptr) {
        funInputEvent_((libinput_event *)lpEvent, frameTime);
        free(lpEvent);
        lpEvent = nullptr;
        MMI_HILOGI("Virtual TrackPad send: LIBINPUT_EVENT_POINTER_TAP RELEASED");
    }
    resetVTrackpadState_();
    SafeDestroyVTrackPadDelayedEvent();
}

void LibinputAdapter::InjectEventForTwoFingerOnTouchpad(libinput_event_touch* touch,
    libinput_event_type eventType, int64_t frameTime)
{
    event_touch tEvent;
    tEvent.event_type = eventType;
    tEvent.seat_slot = VKEY_PINCH_FIRST_FINGER_ID;
    libinput_event_touch* ltEvent = libinput_create_touch_event(touch, tEvent);
    if (ltEvent != nullptr) {
        funInputEvent_((libinput_event*)ltEvent, frameTime);
        free(ltEvent);
        ltEvent = nullptr;
    }
    tEvent.seat_slot = VKEY_PINCH_SECOND_FINGER_ID;
    ltEvent = libinput_create_touch_event(touch, tEvent);
    if (ltEvent != nullptr) {
        funInputEvent_((libinput_event*)ltEvent, frameTime);
        free(ltEvent);
        ltEvent = nullptr;
    }
}

void LibinputAdapter::InjectEventForCastWindow(libinput_event_touch* touch)
{
    int64_t frameTime = GetSysClockTime();
    InjectEventForTwoFingerOnTouchpad(touch, libinput_event_type::LIBINPUT_EVENT_TOUCHPAD_UP, frameTime);

    event_touch tEvent;
    tEvent.seat_slot = VKEY_PINCH_FIRST_FINGER_ID;

    auto mouseInfo = WIN_MGR->GetMouseInfo();
    tEvent.event_type = libinput_event_type::LIBINPUT_EVENT_TOUCH_DOWN;
    tEvent.x = mouseInfo.physicalX * VKEY_RAW_COORDINATE_RATIO;
    tEvent.y = mouseInfo.physicalY * VKEY_RAW_COORDINATE_RATIO;
    tEvent.seat_slot = 0;
    tEvent.slot = 0;
    libinput_event_touch* ltEvent = libinput_create_touch_event(touch, tEvent);
    if (ltEvent != nullptr) {
        funInputEvent_((libinput_event*)ltEvent, frameTime);
        free(ltEvent);
        ltEvent = nullptr;
    }

    tEvent.event_type = libinput_event_type::LIBINPUT_EVENT_TOUCH_UP;
    ltEvent = libinput_create_touch_event(touch, tEvent);
    if (ltEvent != nullptr) {
        funInputEvent_((libinput_event*)ltEvent, frameTime);
        free(ltEvent);
        ltEvent = nullptr;
    }

    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD;
    pEvent.delta_raw_x = VKEY_PINCH_CURSOR_FAKE_DX;
    pEvent.delta_raw_y = 0;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    if (lpEvent != nullptr) {
        funInputEvent_((libinput_event*)lpEvent, frameTime);
        free(lpEvent);
        lpEvent = nullptr;
    }
}

bool LibinputAdapter::IsCursorInCastWindow()
{
    InputWindowsManager* inputWindowsManager = static_cast<InputWindowsManager *>(WIN_MGR.get());
    if (inputWindowsManager == nullptr) {
        return false;
    }
    return inputWindowsManager->IsMouseInCastWindow();
}

int32_t LibinputAdapter::ConvertToTouchEventType(
    libinput_event_type eventType)
{
    if (eventType == LIBINPUT_EVENT_TOUCH_DOWN) {
        return static_cast<int32_t>(VKeyboardTouchEventType::TOUCH_DOWN);
    } else if (eventType == LIBINPUT_EVENT_TOUCH_UP) {
        return static_cast<int32_t>(VKeyboardTouchEventType::TOUCH_UP);
    } else if (eventType == LIBINPUT_EVENT_TOUCH_FRAME) {
        return static_cast<int32_t>(VKeyboardTouchEventType::TOUCH_FRAME);
    } else {
        return static_cast<int32_t>(VKeyboardTouchEventType::TOUCH_MOVE);
    }
}

void LibinputAdapter::HandleHWKeyEventForVKeyboard(libinput_event* event)
{
    MMI_HILOGD("Hardware keyboard key event detected");
    if (hardwareKeyEventDetected_ == nullptr) {
        return;
    }
    if (event == nullptr) {
        MMI_HILOGD("libinput event is nullptr");
        return;
    }
    libinput_event_type eventType = libinput_event_get_type(event);
    if (eventType == LIBINPUT_EVENT_KEYBOARD_KEY) {
        libinput_event_keyboard* keyboardEvent = libinput_event_get_keyboard_event(event);
        if (keyboardEvent == nullptr) {
            MMI_HILOGD("keyboardEvent is nullptr");
            return;
        }
        libinput_device* device = libinput_event_get_device(event);
        if (device == nullptr) {
            MMI_HILOGD("keyboard device is nullptr");
            return;
        }
        uint32_t keyCode = libinput_event_keyboard_get_key(keyboardEvent);
        auto keyValueInfo = TransferKeyValue(static_cast<int32_t>(keyCode));
        int32_t hasFnKey = libinput_device_has_key(device, LIBINPUT_KEY_FN);
        MMI_HILOGD("The current keyCode:%{private}u, hasFnKey:%{private}d, keyName:%{private}s",
            keyCode, hasFnKey, keyValueInfo.keyEvent.c_str());
        if ((keyCode == LIBINPUT_KEY_VOLUME_DOWN || keyCode == LIBINPUT_KEY_VOLUME_UP ||
            keyCode == LIBINPUT_KEY_POWER) && !hasFnKey) {
            MMI_HILOGD("Skip device local button keyCode:%{private}u", keyCode);
            return;
        }
        hardwareKeyEventDetected_(keyValueInfo.keyEvent);
    }
}

void LibinputAdapter::HideMouseCursorTemporary()
{
    MMI_HILOGI("VKeyboard hide mouse.");
    auto& instance = CursorDrawingComponent::GetInstance();
    if (instance.GetMouseDisplayState()) {
        instance.SetMouseDisplayState(false);
    }
}

double LibinputAdapter::GetAccumulatedPressure(int touchId, int32_t eventType, double touchPressure)
{
    auto pos = touchPointPressureCache_.find(touchId);
    double accumulatedPressure = 0.0;
    if (pos != touchPointPressureCache_.end()) {
        accumulatedPressure = pos->second;
    }

    accumulatedPressure += touchPressure;
    touchPointPressureCache_[touchId] = accumulatedPressure;

    if (eventType == LIBINPUT_EVENT_TOUCH_UP) {
        pos = touchPointPressureCache_.find(touchId);
        if (pos != touchPointPressureCache_.end()) {
            touchPointPressureCache_.erase(pos);
        }
    }

    return accumulatedPressure;
}

bool LibinputAdapter::IsVKeyboardActivationDropEvent(libinput_event_touch* touch, libinput_event_type eventType)
{
    bool bDropEventFlag = false;
    if (getKeyboardActivationState_ != nullptr) {
        VKeyboardActivation activateState = (VKeyboardActivation)getKeyboardActivationState_();
        switch (activateState) {
            case VKeyboardActivation::INACTIVE: {
                break;
            }
            case VKeyboardActivation::ACTIVATED: {
                MMI_HILOGD("activation state: %{public}d", static_cast<int32_t>(activateState));
                break;
            }
            case VKeyboardActivation::TOUCH_CANCEL: {
                MMI_HILOGI(
                    "activation state: %{public}d, sending touch cancel event", static_cast<int32_t>(activateState));
                if (eventType == LIBINPUT_EVENT_TOUCH_MOTION) {
                    libinput_set_touch_event_type(touch, LIBINPUT_EVENT_TOUCH_CANCEL);
                }
                if (eventType == LIBINPUT_EVENT_TOUCH_DOWN) {
                    bDropEventFlag = true;
                }
                break;
            }
            case VKeyboardActivation::TOUCH_DROP: {
                MMI_HILOGD("activation state: %{public}d, dropping event", static_cast<int32_t>(activateState));
                if (eventType != LIBINPUT_EVENT_TOUCH_UP) {
                    bDropEventFlag = true;
                }
                break;
            }
            case VKeyboardActivation::EIGHT_FINGERS_UP: {
                MMI_HILOGI("activation state: %{public}d", static_cast<int32_t>(activateState));
                break;
            }
            default:
                break;
        }
    }
    return bDropEventFlag;
}

void LibinputAdapter::UpdateBootFlag()
{
    // check booted flag from parameters.
    if (!isBootCompleted_) {
        isBootCompleted_ = OHOS::system::GetBoolParameter("bootevent.boot.completed", false);
        if (isBootCompleted_) {
            MMI_HILOGI("backend booted from Parameter manager (mainly due to process restart)=%{public}d",
                static_cast<int32_t>(isBootCompleted_));
            return;
        }
    }
    // check booted flag from UI status.
    if (!isBootCompleted_ && isVKeyboardShown_ != nullptr) {
        isBootCompleted_ = isVKeyboardShown_();
        if (isBootCompleted_) {
            MMI_HILOGI("backend booted from VKeyboard UI (mainly due to process restart)=%{public}d",
                static_cast<int32_t>(isBootCompleted_));
        }
    }
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

void LibinputAdapter::MultiKeyboardSetLedState(bool newCapsLockState)
{
    std::vector<struct libinput_device*> input_device;
    INPUT_DEV_MGR->GetMultiKeyboardDevice(input_device);
    for (auto it = input_device.begin(); it != input_device.end(); ++it) {
        auto setDevice = (*it);
        CHKPV(setDevice);
        DeviceLedUpdate(setDevice, KeyEvent::CAPS_LOCK_FUNCTION_KEY, newCapsLockState);
    }
}

void LibinputAdapter::MultiKeyboardSetFuncState(libinput_event* event)
{
    libinput_event_type eventType = libinput_event_get_type(event);
    if (eventType == LIBINPUT_EVENT_KEYBOARD_KEY) {
            struct libinput_event_keyboard* keyboardEvent = libinput_event_get_keyboard_event(event);
            CHKPV(keyboardEvent);
            std::shared_ptr<KeyEvent> keyEvent = KeyEventHdr->GetKeyEvent();
            if (libinput_event_keyboard_get_key_state(keyboardEvent) == LIBINPUT_KEY_STATE_PRESSED
			   && libinput_event_keyboard_get_key(keyboardEvent) == KEY_CAPSLOCK
			   && keyEvent != nullptr) {
                bool oldCapsLockOn = keyEvent->GetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY);
                MultiKeyboardSetLedState(!oldCapsLockOn);
                keyEvent->SetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY, !oldCapsLockOn);
                libinput_toggle_caps_key();
            }
    }
}

void LibinputAdapter::OnEventHandler()
{
    CALL_DEBUG_ENTER;
    CHKPV(funInputEvent_);
    libinput_event *event = nullptr;
    int64_t frameTime = GetSysClockTime();
    while ((event = libinput_get_event(input_))) {
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
        foldingAreaToast_.FoldingAreaProcess(event);
        libinput_event_type eventType = libinput_event_get_type(event);
        int32_t touchId = 0;
        libinput_event_touch* touch = nullptr;
        static int32_t downCount = 0;
        bool isInsideWindow = false;

        // confirm boot completed msg in case of mmi restart.
        UpdateBootFlag();

        // add the logic of screen capture window conuming touch point in high priority
        bool isCaptureMode = GetIsCaptureMode();
        if (((eventType == LIBINPUT_EVENT_TOUCH_DOWN && !isCaptureMode)
            || eventType == LIBINPUT_EVENT_TOUCH_UP
            || eventType == LIBINPUT_EVENT_TOUCH_MOTION
            || eventType == LIBINPUT_EVENT_TOUCH_CANCEL
            || eventType == LIBINPUT_EVENT_TOUCH_FRAME) && isBootCompleted_) {
            touch = libinput_event_get_touch_event(event);
            double touchPressure = 0.0;
            double accumulatedPressure = 0.0;
            if (eventType != LIBINPUT_EVENT_TOUCH_FRAME) {
                touchId = libinput_event_touch_get_slot(touch);
                touchPressure = libinput_event_touch_get_pressure(touch);
                accumulatedPressure = GetAccumulatedPressure(touchId, eventType, touchPressure);
            }

            if (deviceId == -1) {
                // initialize touch device ID.
                libinput_device* device = libinput_event_get_device(event);
                deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
            }

            EventTouch touchInfo;
            int32_t logicalDisplayId = -1;
            double x = 0.0;
            double y = 0.0;
            int32_t touchEventType = ConvertToTouchEventType(eventType);
            // touch up event has no coordinates information, skip coordinate calculation.
            if (eventType == LIBINPUT_EVENT_TOUCH_DOWN || eventType == LIBINPUT_EVENT_TOUCH_MOTION) {
                if (!WIN_MGR->TouchPointToDisplayPoint(deviceId, touch, touchInfo, logicalDisplayId)) {
                    MMI_HILOGE("Map touch point to display point failed");
                } else {
                    x = touchInfo.point.x;
                    y = touchInfo.point.y;

                    touchPoints_[touchId] = std::pair<double, double>(x, y);

                    InputWindowsManager* inputWindowsManager = static_cast<InputWindowsManager *>(WIN_MGR.get());
                    isInsideWindow = inputWindowsManager->IsPointInsideSpecialWindow(x, y);
                }
            } else if (eventType == LIBINPUT_EVENT_TOUCH_UP) {
                auto pos = touchPoints_.find(touchId);
                if (pos != touchPoints_.end()) {
                    x = (pos->second).first;
                    y = (pos->second).second;
                    touchPoints_.erase(pos);
                }
            }

            int32_t longAxis = libinput_event_get_touch_contact_long_axis(touch);
            int32_t shortAxis = libinput_event_get_touch_contact_short_axis(touch);
            MMI_HILOGD("touch event. deviceId:%{private}d, touchId:%{private}d, x:%{private}d, y:%{private}d, \
type:%{private}d, accPressure:%{private}f, longAxis:%{private}d, shortAxis:%{private}d",
                deviceId,
                touchId,
                static_cast<int32_t>(x),
                static_cast<int32_t>(y),
                static_cast<int32_t>(eventType),
                accumulatedPressure,
                longAxis,
                shortAxis);

            if (!isInsideWindow && handleTouchPoint_ != nullptr &&
                handleTouchPoint_(x, y, touchId, touchEventType, accumulatedPressure, longAxis, shortAxis) == 0) {
                MMI_HILOGD("Inside vkeyboard area");
                HandleVFullKeyboardMessages(event, frameTime, eventType, touch);
            } else {
                bool bDropEventFlag = IsVKeyboardActivationDropEvent(touch, eventType);
                if (!bDropEventFlag) {
                    funInputEvent_(event, frameTime);
                }
                libinput_event_destroy(event);
            }
        } else if (eventType == LIBINPUT_EVENT_KEYBOARD_KEY) {
            struct libinput_event_keyboard* keyboardEvent = libinput_event_get_keyboard_event(event);
            std::shared_ptr<KeyEvent> keyEvent = KeyEventHdr->GetKeyEvent();

            if (libinput_event_keyboard_get_key_state(keyboardEvent) == LIBINPUT_KEY_STATE_PRESSED &&
                libinput_event_keyboard_get_key(keyboardEvent) == KEY_CAPSLOCK && keyEvent != nullptr) {
                bool oldCapsLockOn = keyEvent->GetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY);
                HandleHWKeyEventForVKeyboard(event);
                funInputEvent_(event, frameTime);
                libinput_event_destroy(event);
                MultiKeyboardSetLedState(!oldCapsLockOn);
                keyEvent->SetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY, !oldCapsLockOn);
                libinput_toggle_caps_key();
            } else {
                HandleHWKeyEventForVKeyboard(event);
                funInputEvent_(event, frameTime);
                libinput_event_destroy(event);
            }
        } else {
            funInputEvent_(event, frameTime);
            libinput_event_destroy(event);
        }
#else // OHOS_BUILD_ENABLE_VKEYBOARD
        MultiKeyboardSetFuncState(event);
        funInputEvent_(event, frameTime);
        libinput_event_destroy(event);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    }
    if (event == nullptr) {
        funInputEvent_(nullptr, 0);
    }
}

void LibinputAdapter::ReloadDevice()
{
    CALL_DEBUG_ENTER;
    CHKPV(input_);
    libinput_suspend(input_);
    libinput_resume(input_);
}

void LibinputAdapter::OnDeviceAdded(std::string path)
{
    std::regex re("(\\d+)");
    std::string str_path(path);
    std::smatch match;
    int32_t id;
    bool isPath = std::regex_search(str_path, match, re);
    if (!isPath) {
        id = -1;
    } else {
        id = std::stoi(match[0]);
    }
    MMI_HILOGI("OnDeviceAdded id:%{public}d", id);
    auto pos = devices_.find(path);
    if (pos != devices_.end()) {
        MMI_HILOGD("Path is found");
        return;
    }

    DTaskCallback cb = [this, path] {
        MMI_HILOGI("OnDeviceAdded, path:%{private}s", path.c_str());
        udev_device_record_devnode(path.c_str());
        libinput_device* device = libinput_path_add_device(input_, path.c_str());
        if (device != nullptr) {
            devices_[std::move(path)] = libinput_device_ref(device);
            // Libinput doesn't signal device adding event in path mode. Process manually.
            OnEventHandler();
        }
        udev_device_property_remove(path.c_str());
        return 0;
    };
    PropReader->ReadPropertys(path, cb);
}

void LibinputAdapter::OnDeviceRemoved(std::string path)
{
    std::regex re("(\\d+)");
    std::string str_path(path);
    std::smatch match;
    int32_t id;
    bool isPath = std::regex_search(str_path, match, re);
    if (!isPath) {
        id = -1;
    } else {
        id = std::stoi(match[0]);
    }
    MMI_HILOGI("OnDeviceRemoved id:%{public}d", id);
    auto pos = devices_.find(path);
    if (pos != devices_.end()) {
        libinput_path_remove_device(pos->second);
        libinput_device_unref(pos->second);
        devices_.erase(pos);
        // Libinput doesn't signal device removing event in path mode. Process manually.
        OnEventHandler();
    }
}
} // namespace MMI
} // namespace OHOS
