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
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
#include <common_event_manager.h>
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

#include "param_wrapper.h"
#include "property_reader.h"
#include "input_device_manager.h"
#include "input_windows_manager.h"
#include "key_event_normalize.h"
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
#include "key_event_value_transformation.h"
#include "timer_manager.h"
#include <shared_mutex>
#include "common_event_manager.h"
#include "common_event_support.h"
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

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
constexpr int32_t VKEY_TP_SM_MSG_SIZE { 6 };
constexpr int32_t VKEY_TP_SM_MSG_TYPE_IDX { 0 };
constexpr int32_t VKEY_TP_SM_MSG_POINTER_ID_IDX { 1 };
constexpr int32_t VKEY_TP_SM_MSG_POS_X_IDX { 2 };
constexpr int32_t VKEY_TP_SM_MSG_POS_Y_IDX { 3 };
constexpr int32_t VKEY_TP_SM_MSG_SCALE_IDX { 4 };
constexpr int32_t VKEY_TP_SM_MSG_ANGLE_IDX { 5 };
constexpr int32_t VKEY_TP_GSE_TWO_FINGERS { 2 };
constexpr int32_t VKEY_TP_GSE_THREE_FINGERS { 3 };
constexpr int32_t VKEY_TP_GSE_FOUR_FINGERS { 4 };
constexpr uint32_t VKEY_TP_LB_ID { 272 };
constexpr uint32_t VKEY_TP_RB_ID { 273 };
constexpr uint32_t VKEY_TP_SEAT_BTN_COUNT_NONE { 0 };
constexpr uint32_t VKEY_TP_SEAT_BTN_COUNT_ONE { 1 };
constexpr uint32_t VKEY_TP_AXES_ZERO { 0 };
constexpr uint32_t VKEY_TP_AXES_ONE { 1 };
constexpr uint32_t VKEY_TP_AXES_TWO { 2 };
constexpr double VTP_SCALE_AND_ANGLE_FACTOR { 1000.0 };
constexpr uint32_t KEY_CAPSLOCK { 58 };
constexpr uint32_t LIBINPUT_KEY_VOLUME_DOWN { 114 };
constexpr uint32_t LIBINPUT_KEY_VOLUME_UP { 115 };
constexpr uint32_t LIBINPUT_KEY_POWER { 116 };
constexpr uint32_t LIBINPUT_KEY_FN { 240 };
constexpr float SCREEN_CAPTURE_WINDOW_ZORDER { 8000.0 };
constexpr double VTP_LEFT_BUTTON_DELTA_X { 0.0 };
constexpr double VTP_LEFT_BUTTON_DELTA_Y { -1.0 };
constexpr uint32_t VKEY_PINCH_FIRST_FINGER_ID { 0 };
constexpr uint32_t VKEY_PINCH_SECOND_FINGER_ID { 1 };
constexpr float VKEY_RAW_COORDINATE_RATIO { 8.0 };
constexpr uint32_t VKEY_PINCH_CURSOR_FAKE_DX { 1 };
constexpr uint32_t WINDOW_NAME_TYPE_SCHREENSHOT { 1 };
enum class VKeyboardTouchEventType : int32_t {
    TOUCH_DOWN = 0,
    TOUCH_UP = 1,
    TOUCH_MOVE = 2,
    TOUCH_FRAME = 3,
};
#define SCREEN_RECORD_WINDOW_WIDTH 400
#define SCREEN_RECORD_WINDOW_HEIGHT 200
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
            MMI_HILOGWK("The error path is %{public}s", path);
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
        MMI_HILOGWK("Libinput .open_restricted id:%{public}d, fd:%{public}d, errno:%{public}d",
            id, fd, errNo);
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
    funInputEvent_ = funInputEvent;
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
    GetMessage getMessage,
    GetAllTouchMessage getAllTouchMessage,
    ClearTouchMessage clearTouchMessage,
    GetAllKeyMessage getAllKeyMessage,
    ClearKeyMessage clearKeyMessage,
    HardwareKeyEventDetected hardwareKeyEventDetected,
    GetKeyboardActivationState getKeyboardActivationState,
    IsFloatingKeyboard isFloatingKeyboard,
    IsVKeyboardShown isVKeyboardShown)
{
    handleTouchPoint_ = handleTouchPoint;
    getMessage_ = getMessage;
    getAllTouchMessage_ = getAllTouchMessage;
    clearTouchMessage_ = clearTouchMessage;
    getAllKeyMessage_ = getAllKeyMessage;
    clearKeyMessage_ = clearKeyMessage;
    hardwareKeyEventDetected_ = hardwareKeyEventDetected;
    getKeyboardActivationState_ = getKeyboardActivationState;
    isFloatingKeyboard_ = isFloatingKeyboard;
    isVKeyboardShown_ = isVKeyboardShown;

    // init touch device Id.
    deviceId = -1;
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
void LibinputAdapter::DelayInjectKeyEventCallback()
{
    MMI_HILOGI("Delayed done for kc:%{private}d.", vkbDelayedKeyCode_);
    CHKPV(vkbDelayedEvent_);
    libinput_event_touch *touch = libinput_event_get_touch_event(vkbDelayedEvent_);
    CHKPV(touch);
    libinput_event_keyboard *key_event_pressed = libinput_create_keyboard_event(
        touch, vkbDelayedKeyCode_, libinput_key_state::LIBINPUT_KEY_STATE_RELEASED);
    CHKPV(funInputEvent_);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event *)key_event_pressed, frameTime);
    free(key_event_pressed);
    libinput_event_destroy(vkbDelayedEvent_);
    vkbDelayedEvent_ = nullptr;
}

// return true if timer has started successfully.
bool LibinputAdapter::CreateVKeyboardDelayTimer(libinput_event *event, int32_t delayMs, int32_t keyCode)
{
    if (vkbDelayedEvent_ != nullptr) {
        MMI_HILOGI("A delayed event is pending, skip delay msg for KC=%{private}d, Delay=%{public}d",
            keyCode, delayMs);
        return false;
    }

    vkbDelayedEvent_ = event;
    vkbDelayedKeyCode_ = keyCode;
    MMI_HILOGI("Create the delayed event for KC=%{private}d, Delay=%{public}d", keyCode, delayMs);
    return true;
}

void LibinputAdapter::StartVKeyboardDelayTimer(int32_t delayMs)
{
    TimerMgr->AddTimer(delayMs, 1, [this]() {
        DelayInjectKeyEventCallback();
    });
}

bool LibinputAdapter::GetIsCaptureMode()
{
    bool isCaptureMode = false;
    bool hasScreenShotWindow = false;

    InputWindowsManager* inputWindowsManager = static_cast<InputWindowsManager *>(WIN_MGR.get());
    if (inputWindowsManager != nullptr) {
        DisplayGroupInfo displayGroupInfo = inputWindowsManager->GetDisplayGroupInfo();
        bool isFloating = false;
        for (auto &windowInfo : displayGroupInfo.windowsInfo) {
            if (windowInfo.windowNameType == WINDOW_NAME_TYPE_SCHREENSHOT) {
                hasScreenShotWindow = true;
            }

            if (windowInfo.zOrder == SCREEN_CAPTURE_WINDOW_ZORDER) {
                // screen recorder scenario will be an exception to true
                isFloating = (isFloatingKeyboard_ == nullptr) ? false : isFloatingKeyboard_();
                isCaptureMode = (((windowInfo.area.width > SCREEN_RECORD_WINDOW_WIDTH) \
                    || (windowInfo.area.height > SCREEN_RECORD_WINDOW_HEIGHT)) && isFloating) ? true : false;
                MMI_HILOGD("#####Currently keyboard will %s consume touch points", (isCaptureMode ? "not" : ""));
                break;
            }
        }

        if (hasScreenShotWindow) {
            isCaptureMode = false;
        }
    }

    return isCaptureMode;
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

void LibinputAdapter::InjectKeyEvent(libinput_event_touch* touch, int32_t keyCode,
                                     libinput_key_state state, int64_t frameTime)
{
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    // Note: during caps lock down, the vkeyboardData.capsLock inside libinput is toggled.
    libinput_event_keyboard* key_event_pressed =
            libinput_create_keyboard_event(touch, keyCode, state);

    if (keyCode == KEY_CAPSLOCK && state == libinput_key_state::LIBINPUT_KEY_STATE_PRESSED) {
        struct libinput_device* device = INPUT_DEV_MGR->GetKeyboardDevice();
        if (device != nullptr) {
            std::shared_ptr<KeyEvent> keyEvent = KeyEventHdr->GetKeyEvent();
            if (keyEvent != nullptr) {
                bool isCapsLockOn = keyEvent->GetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY);

                DeviceLedUpdate(device, KeyEvent::CAPS_LOCK_FUNCTION_KEY, !isCapsLockOn);
                keyEvent->SetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY, !isCapsLockOn);
            }
        }
    }

    funInputEvent_((libinput_event*)key_event_pressed, frameTime);
    free(key_event_pressed);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
void LibinputAdapter::HandleVFullKeyboardMessages(
    libinput_event *event, int64_t frameTime, libinput_event_type eventType, libinput_event_touch *touch)
{
    // delay the event destroy.
    bool delayDestroy = false;
    int32_t confirmedDelayMs(0);

    // handle keyboard and trackpad messages.
    while (true) {
        int32_t delayMs(0);
        int32_t toggleCodeSecond(0);
        int32_t keyCode(0);
        VKeyboardMessageType type = (VKeyboardMessageType)getMessage_(delayMs, toggleCodeSecond, keyCode);
        MMI_HILOGD("Get message type:%{private}d", static_cast<int32_t>(type));
        if (type == VNoMessage) {
            break;
        }

        // if need to delay, not injecting but store them. Limit to up event.
        if (delayMs > 0 && type == VKeyboardMessageType::VStopLongPressControl && !delayDestroy) {
            // start delaying.
            delayDestroy = CreateVKeyboardDelayTimer(event, delayMs, keyCode);
            if (delayDestroy) {
                // create and delay this event.
                confirmedDelayMs = delayMs;
                continue;
            }
        }
        // otherwise, do regular processing in real-time.
        switch (type) {
            case VKeyboardMessageType::VKeyPressed: {
                MMI_HILOGD("press key:%{private}d", keyCode);
                InjectKeyEvent(touch, keyCode, libinput_key_state::LIBINPUT_KEY_STATE_PRESSED, frameTime);
                InjectKeyEvent(touch, keyCode, libinput_key_state::LIBINPUT_KEY_STATE_RELEASED, frameTime);
                break;
            }
            case VKeyboardMessageType::VStartLongPressControl: {
                MMI_HILOGD("long press start:%{private}d", keyCode);
                InjectKeyEvent(touch, keyCode, libinput_key_state::LIBINPUT_KEY_STATE_PRESSED, frameTime);
                break;
            }
            case VKeyboardMessageType::VStopLongPressControl: {
                MMI_HILOGD("long press stop:%{private}d", keyCode);
                InjectKeyEvent(touch, keyCode, libinput_key_state::LIBINPUT_KEY_STATE_RELEASED, frameTime);
                break;
            }
            case VKeyboardMessageType::VSwitchLayout: {
                HideMouseCursorTemporary();
                break;
            }
            default:
                break;
        }
    }
    HandleVKeyTouchpadMessages(touch);

    if (eventType == LIBINPUT_EVENT_TOUCH_FRAME) {
        // still let frame info go through.
        funInputEvent_(event, frameTime);
    }
    if (delayDestroy) {
        StartVKeyboardDelayTimer(confirmedDelayMs);
    } else {
        libinput_event_destroy(event);
    }
}

void LibinputAdapter::HandleVKeyTouchpadMessages(libinput_event_touch* touch)
{
    // Handle all track pad key messages
    std::vector<std::vector<int32_t>> keyMsgList;
    if (getAllKeyMessage_ != nullptr) {
        getAllKeyMessage_(keyMsgList);
    }
    if (clearKeyMessage_ != nullptr) {
        clearKeyMessage_();
    }
    if (!keyMsgList.empty()) {
        ShowMouseCursor();
    }
    OnVKeyTrackPadMessage(touch, keyMsgList);
    // Handle all track pad touch messages
    std::vector<std::vector<int32_t>> touchMsgList;
    if (getAllTouchMessage_ != nullptr) {
        getAllTouchMessage_(touchMsgList);
    }
    if (clearTouchMessage_ != nullptr) {
        clearTouchMessage_();
    }
    if (!touchMsgList.empty()) {
        ShowMouseCursor();
    }
    OnVKeyTrackPadMessage(touch, touchMsgList);
}
void LibinputAdapter::update_pointer_move(auto msgType)
{
    if (msgType != VTPStateMachineMessageType::POINTER_MOVE) {
        pointer_move_count = 0;
    }
}

void LibinputAdapter::CheckSwipeState(libinput_event_touch* touch,
    VTPStateMachineMessageType msgType, const std::vector<int32_t>& msgItem)
{
    if (vtpSwipeState_ == VTPSwipeStateType::SWIPE_BEGIN &&
        msgType != VTPStateMachineMessageType::SWIPE_UPDATE &&
        msgType != VTPStateMachineMessageType::SWIPE_END) {
        HandleVKeyTrackPadSwipeEnd(touch, msgItem);
    }
    update_pointer_move(msgType);
}

void LibinputAdapter::OnVKeyTrackPadMessage(libinput_event_touch* touch,
    const std::vector<std::vector<int32_t>>& msgList)
{
    for (auto msgItem : msgList) {
        if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
            MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
                static_cast<int32_t>(msgItem.size()));
            continue;
        }
        auto msgType = static_cast<VTPStateMachineMessageType>(msgItem[VKEY_TP_SM_MSG_TYPE_IDX]);
        CheckSwipeState(touch, msgType, msgItem);
        switch (msgType) {
            case VTPStateMachineMessageType::POINTER_MOVE:
                if (!HandleVKeyTrackPadPointerMove(touch, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad pointer move event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::LEFT_CLICK_DOWN:
                if (!HandleVKeyTrackPadLeftBtnDown(touch, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad left button down event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::LEFT_TOUCH_DOWN:
                if (!HandleVKeyTrackPadTouchPadDown(touch, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad Touchpad down event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::LEFT_CLICK_UP:
                if (!HandleVKeyTrackPadLeftBtnUp(touch, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad left button up event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::LEFT_TOUCH_UP:
                if (!HandleVKeyTrackPadTouchPadUp(touch, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad Touchpad up event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::RIGHT_CLICK_DOWN:
                if (!HandleVKeyTrackPadRightBtnDown(touch, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad right button down event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::RIGHT_CLICK_UP:
                if (!HandleVKeyTrackPadRightBtnUp(touch, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad right button up event cannot be handled");
                }
                break;
            case VTPStateMachineMessageType::TWO_FINGER_TAP:
                if (!HandleVKeyTrackPadTwoFingerTap(touch, msgItem)) {
                    MMI_HILOGE("Virtual TrackPad two finger tap event cannot be handled");
                }
                break;
            default:
                OnVKeyTrackPadGestureMessage(touch, msgType, msgItem);
                break;
        }
    }
}

void LibinputAdapter::OnVKeyTrackPadGestureMessage(libinput_event_touch* touch,
    VTPStateMachineMessageType msgType, const std::vector<int32_t>& msgItem)
{
    switch (msgType) {
        case VTPStateMachineMessageType::SCROLL_BEGIN:
            if (!HandleVKeyTrackPadScrollBegin(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad scroll begin event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::SCROLL_UPDATE:
            if (!HandleVKeyTrackPadScrollUpdate(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad scroll update event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::SCROLL_END:
            if (!HandleVKeyTrackPadScrollEnd(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad scroll end event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::PINCH_BEGIN:
            if (!HandleVKeyTrackPadPinchBegin(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad pinch begin event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::PINCH_UPDATE:
            if (!HandleVKeyTrackPadPinchUpdate(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad pinch update event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::PINCH_END:
            if (!HandleVKeyTrackPadPinchEnd(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad pinch end event cannot be handled");
            }
            break;
        default:
            OnVKeyTrackPadGestureTwoMessage(touch, msgType, msgItem);
            break;
    }
}

void LibinputAdapter::OnVKeyTrackPadGestureTwoMessage(libinput_event_touch* touch,
    VTPStateMachineMessageType msgType, const std::vector<int32_t>& msgItem)
{
    switch (msgType) {
        case VTPStateMachineMessageType::PAN_BEGIN:
            if (!HandleVKeyTrackPadPanBegin(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad pan begin event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::PAN_UPDATE:
            if (!HandleVKeyTrackPadPanUpdate(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad pan update event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::PAN_END:
            if (!HandleVKeyTrackPadPanEnd(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad pan end event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::ROT_BEGIN:
            if (!HandleVKeyTrackPadRotateBegin(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad rotate begin event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::ROT_UPDATE:
            if (!HandleVKeyTrackPadRotateUpdate(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad rotate update event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::ROT_END:
            if (!HandleVKeyTrackPadRotateEnd(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad rotate end event cannot be handled");
            }
            break;
        default:
            OnVKeyTrackPadGestureThreeMessage(touch, msgType, msgItem);
            break;
    }
}

void LibinputAdapter::OnVKeyTrackPadGestureThreeMessage(libinput_event_touch* touch,
    VTPStateMachineMessageType msgType, const std::vector<int32_t>& msgItem)
{
    switch (msgType) {
        case VTPStateMachineMessageType::SWIPE_BEGIN:
            if (!HandleVKeyTrackPadSwipeBegin(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad swipe begin event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::SWIPE_UPDATE:
            if (!HandleVKeyTrackPadSwipeUpdate(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad swipe update event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::SWIPE_END:
            if (!HandleVKeyTrackPadSwipeEnd(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad swipe end event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::SWIPE_FOUR_BEGIN:
            if (!HandleVKeyTrackPadSwipeFourBegin(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad swipe four begin event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::SWIPE_FOUR_UPDATE:
            if (!HandleVKeyTrackPadSwipeFourUpdate(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad swipe four update event cannot be handled");
            }
            break;
        case VTPStateMachineMessageType::SWIPE_FOUR_END:
            if (!HandleVKeyTrackPadSwipeFourEnd(touch, msgItem)) {
                MMI_HILOGE("Virtual TrackPad swipe four end event cannot be handled");
            }
            break;
    }
}

bool LibinputAdapter::HandleVKeyTrackPadSwipeBegin(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (vtpSwipeState_ != VTPSwipeStateType::SWIPE_END) {
        HandleVKeyTrackPadSwipeEnd(touch, msgItem);
        return false;
    }
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN;
    gEvent.finger_count = VKEY_TP_GSE_THREE_FINGERS;
    sloted_coords_info slotInfo = {};
    slotInfo.active_count = VKEY_TP_GSE_THREE_FINGERS;
    slotInfo.coords[0].is_active = true;
    slotInfo.coords[0].x = static_cast<float>(msgPPosX);
    slotInfo.coords[0].y = static_cast<float>(msgPPosY);
    slotInfo.coords[0].is_active = true;
    slotInfo.coords[1].x = static_cast<float>(msgPPosX);
    slotInfo.coords[1].y = static_cast<float>(msgPPosY);
    slotInfo.coords[1].is_active = true;
    gEvent.solt_touches = slotInfo;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
    vtpSwipeState_ = VTPSwipeStateType::SWIPE_BEGIN;
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadSwipeUpdate(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (vtpSwipeState_ == VTPSwipeStateType::SWIPE_END) {
        return false;
    }
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t msgPSwipe = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE;
    gEvent.finger_count = VKEY_TP_GSE_THREE_FINGERS;
    gEvent.delta_x = 0;
    gEvent.delta_y = msgPSwipe;
    gEvent.delta_unaccel_x = 0;
    gEvent.delta_unaccel_y = msgPSwipe;
    sloted_coords_info slotInfo = {};
    slotInfo.active_count = VKEY_TP_GSE_THREE_FINGERS;
    slotInfo.coords[0].is_active = true;
    slotInfo.coords[0].x = static_cast<float>(msgPPosX);
    slotInfo.coords[0].y = static_cast<float>(msgPPosY);
    slotInfo.coords[0].is_active = true;
    slotInfo.coords[1].x = static_cast<float>(msgPPosX);
    slotInfo.coords[1].y = static_cast<float>(msgPPosY);
    slotInfo.coords[1].is_active = true;
    gEvent.solt_touches = slotInfo;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
    vtpSwipeState_ = VTPSwipeStateType::SWIPE_UPDATE;
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadSwipeEnd(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (vtpSwipeState_ == VTPSwipeStateType::SWIPE_END) {
        return false;
    }
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t msgPSwipe = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_SWIPE_END;
    gEvent.finger_count = VKEY_TP_GSE_THREE_FINGERS;
    sloted_coords_info slotInfo = {};
    slotInfo.active_count = VKEY_TP_GSE_THREE_FINGERS;
    slotInfo.coords[0].is_active = true;
    slotInfo.coords[0].x = static_cast<float>(msgPPosX);
    slotInfo.coords[0].y = static_cast<float>(msgPPosY);
    slotInfo.coords[0].is_active = true;
    slotInfo.coords[1].x = static_cast<float>(msgPPosX);
    slotInfo.coords[1].y = static_cast<float>(msgPPosY);
    slotInfo.coords[1].is_active = true;
    gEvent.solt_touches = slotInfo;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
    vtpSwipeState_ = VTPSwipeStateType::SWIPE_END;
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadSwipeFourBegin(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_SWIPE_BEGIN;
    gEvent.finger_count = VKEY_TP_GSE_FOUR_FINGERS;
    PrintVKeyTPGestureLog(gEvent);
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
    vtpSwipeState_ = VTPSwipeStateType::SWIPE_BEGIN;
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadSwipeFourUpdate(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_gesture gEvent;
    gEvent.device_coords_x[0] = msgPPosX;
    gEvent.device_coords_y[0] = msgPPosY;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_SWIPE_UPDATE;
    gEvent.finger_count = VKEY_TP_GSE_FOUR_FINGERS;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
    vtpSwipeState_ = VTPSwipeStateType::SWIPE_UPDATE;
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadSwipeFourEnd(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_SWIPE_END;
    gEvent.finger_count = VKEY_TP_GSE_FOUR_FINGERS;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
    vtpSwipeState_ = VTPSwipeStateType::SWIPE_END;
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadPointerMove(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD;
    pEvent.delta_raw_x = msgPPosX;
    pEvent.delta_raw_y = msgPPosY;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadLeftBtnDown(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    pEvent.button = VKEY_TP_LB_ID;
    pEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_ONE;
    pEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_PRESSED;
    pEvent.delta_x = VTP_LEFT_BUTTON_DELTA_X;
    pEvent.delta_y = VTP_LEFT_BUTTON_DELTA_Y;
    pEvent.delta_raw_x = VTP_LEFT_BUTTON_DELTA_X;
    pEvent.delta_raw_y = VTP_LEFT_BUTTON_DELTA_Y;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadTouchPadDown(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_TAP;
    pEvent.button = VKEY_TP_LB_ID;
    pEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_ONE;
    pEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_PRESSED;
    pEvent.delta_x = VTP_LEFT_BUTTON_DELTA_X;
    pEvent.delta_y = VTP_LEFT_BUTTON_DELTA_Y;
    pEvent.delta_raw_x = VTP_LEFT_BUTTON_DELTA_X;
    pEvent.delta_raw_y = VTP_LEFT_BUTTON_DELTA_Y;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadLeftBtnUp(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD;
    pEvent.button = VKEY_TP_LB_ID;
    pEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_NONE;
    pEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_RELEASED;
    pEvent.delta_x = VTP_LEFT_BUTTON_DELTA_X;
    pEvent.delta_y = VTP_LEFT_BUTTON_DELTA_Y;
    pEvent.delta_raw_x = VTP_LEFT_BUTTON_DELTA_X;
    pEvent.delta_raw_y = VTP_LEFT_BUTTON_DELTA_Y;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadTouchPadUp(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_TAP;
    pEvent.button = VKEY_TP_LB_ID;
    pEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_NONE;
    pEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_RELEASED;
    pEvent.delta_x = VTP_LEFT_BUTTON_DELTA_X;
    pEvent.delta_y = VTP_LEFT_BUTTON_DELTA_Y;
    pEvent.delta_raw_x = VTP_LEFT_BUTTON_DELTA_X;
    pEvent.delta_raw_y = VTP_LEFT_BUTTON_DELTA_Y;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadRightBtnDown(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_BUTTON;
    pEvent.button = VKEY_TP_RB_ID;
    pEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_ONE;
    pEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_PRESSED;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadRightBtnUp(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_BUTTON;
    pEvent.button = VKEY_TP_RB_ID;
    pEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_NONE;
    pEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_RELEASED;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadTwoFingerTap(libinput_event_touch* touch, const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int64_t frameTime = GetSysClockTime();
    // tap down
    event_pointer pDownEvent;
    pDownEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_TAP;
    pDownEvent.button = VKEY_TP_RB_ID;
    pDownEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_NONE;
    pDownEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_PRESSED;
    libinput_event_pointer* lpDownEvent = libinput_create_pointer_event(touch, pDownEvent);
    CHKPF(lpDownEvent);
    PrintVKeyTPPointerLog(pDownEvent);
    funInputEvent_((libinput_event*)lpDownEvent, frameTime);
    free(lpDownEvent);

    // tap up
    event_pointer pUpEvent;
    pUpEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_TAP;
    pUpEvent.button = VKEY_TP_RB_ID;
    pUpEvent.seat_button_count = VKEY_TP_SEAT_BTN_COUNT_NONE;
    pUpEvent.state = libinput_button_state::LIBINPUT_BUTTON_STATE_RELEASED;
    libinput_event_pointer* lpUpEvent = libinput_create_pointer_event(touch, pUpEvent);
    CHKPF(lpUpEvent);
    PrintVKeyTPPointerLog(pUpEvent);
    funInputEvent_((libinput_event*)lpUpEvent, frameTime);
    free(lpUpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadScrollBegin(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    MMI_HILOGI("VKey TrackPad Scroll Begin");
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_SCROLL_FINGER_BEGIN;
    pEvent.delta_x = msgPPosX;
    pEvent.delta_y = msgPPosY;
    pEvent.delta_raw_x = msgPPosX;
    pEvent.delta_raw_y = msgPPosY;
    pEvent.axes = VKEY_TP_AXES_ZERO;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadScrollUpdate(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    MMI_HILOGI("VKey TrackPad Scroll Update");
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_AXIS;
    pEvent.delta_x = msgPPosX;
    pEvent.delta_y = msgPPosY;
    pEvent.delta_raw_x = msgPPosX;
    pEvent.delta_raw_y = msgPPosY;
    pEvent.source = libinput_pointer_axis_source::LIBINPUT_POINTER_AXIS_SOURCE_FINGER;
    pEvent.axes = VKEY_TP_AXES_ONE;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_SCROLL_FINGER;
    lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadScrollEnd(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    MMI_HILOGI("VKey TrackPad Scroll End");
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_SCROLL_FINGER_END;
    pEvent.delta_x = msgPPosX;
    pEvent.delta_y = msgPPosY;
    pEvent.delta_raw_x = msgPPosX;
    pEvent.delta_raw_y = msgPPosY;
    pEvent.axes = VKEY_TP_AXES_ZERO;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadPinchBegin(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t msgPScale = msgItem[VKEY_TP_SM_MSG_SCALE_IDX];
    double scaleToDouble = static_cast<double>(msgPScale) / VTP_SCALE_AND_ANGLE_FACTOR;
    int32_t msgPAngle = msgItem[VKEY_TP_SM_MSG_ANGLE_IDX];
    double angleToDouble = static_cast<double>(msgPAngle) / VTP_SCALE_AND_ANGLE_FACTOR;
    MMI_HILOGI("VKey TrackPad Pinch Begin");
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_PINCH_BEGIN;
    gEvent.finger_count = VKEY_TP_GSE_TWO_FINGERS;
    gEvent.cancelled = 0;
    gEvent.delta_x = msgPPosX;
    gEvent.delta_y = msgPPosY;
    gEvent.delta_unaccel_x = msgPPosX;
    gEvent.delta_unaccel_y = msgPPosY;
    sloted_coords_info slotInfo;
    gEvent.solt_touches = slotInfo;
    gEvent.scale = scaleToDouble;
    gEvent.angle = angleToDouble;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    PrintVKeyTPGestureLog(gEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
	
    InjectEventForTwoFingerOnTouchpad(touch, libinput_event_type::LIBINPUT_EVENT_TOUCHPAD_DOWN, frameTime);
	
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadPinchUpdate(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t msgPScale = msgItem[VKEY_TP_SM_MSG_SCALE_IDX];
    double scaleToDouble = static_cast<double>(msgPScale) / VTP_SCALE_AND_ANGLE_FACTOR;
    int32_t msgPAngle = msgItem[VKEY_TP_SM_MSG_ANGLE_IDX];
    double angleToDouble = static_cast<double>(msgPAngle) / VTP_SCALE_AND_ANGLE_FACTOR;
    MMI_HILOGI("VKey TrackPad Pinch Update");
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_PINCH_UPDATE;
    gEvent.finger_count = VKEY_TP_GSE_TWO_FINGERS;
    gEvent.cancelled = 0;
    gEvent.delta_x = msgPPosX;
    gEvent.delta_y = msgPPosY;
    gEvent.delta_unaccel_x = msgPPosX;
    gEvent.delta_unaccel_y = msgPPosY;
    sloted_coords_info slotInfo;
    gEvent.solt_touches = slotInfo;
    gEvent.scale = scaleToDouble;
    gEvent.angle = angleToDouble;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    PrintVKeyTPGestureLog(gEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
	
    InjectEventForTwoFingerOnTouchpad(touch, libinput_event_type::LIBINPUT_EVENT_TOUCHPAD_MOTION, frameTime);
	
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadPinchEnd(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t msgPScale = msgItem[VKEY_TP_SM_MSG_SCALE_IDX];
    double scaleToDouble = static_cast<double>(msgPScale) / VTP_SCALE_AND_ANGLE_FACTOR;
    int32_t msgPAngle = msgItem[VKEY_TP_SM_MSG_ANGLE_IDX];
    double angleToDouble = static_cast<double>(msgPAngle) / VTP_SCALE_AND_ANGLE_FACTOR;
    MMI_HILOGI("VKey TrackPad Pinch End");
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_PINCH_END;
    gEvent.finger_count = VKEY_TP_GSE_TWO_FINGERS;
    gEvent.cancelled = 0;
    gEvent.delta_x = msgPPosX;
    gEvent.delta_y = msgPPosY;
    gEvent.delta_unaccel_x = msgPPosX;
    gEvent.delta_unaccel_y = msgPPosY;
    sloted_coords_info slotInfo;
    gEvent.solt_touches = slotInfo;
    gEvent.scale = scaleToDouble;
    gEvent.angle = angleToDouble;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    PrintVKeyTPGestureLog(gEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
	
    if (IsCursorInCastWindow()) {
        InjectEventForCastWindow(touch);
    } else {
        InjectEventForTwoFingerOnTouchpad(touch, libinput_event_type::LIBINPUT_EVENT_TOUCHPAD_UP, frameTime);
    }

    return true;
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
    }

    tEvent.seat_slot = VKEY_PINCH_SECOND_FINGER_ID;
    ltEvent = libinput_create_touch_event(touch, tEvent);
    if (ltEvent != nullptr) {
        funInputEvent_((libinput_event*)ltEvent, frameTime);
        free(ltEvent);
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
    ltEvent = libinput_create_touch_event(touch, tEvent);
    funInputEvent_((libinput_event*)ltEvent, frameTime);
    free(ltEvent);

    tEvent.event_type = libinput_event_type::LIBINPUT_EVENT_TOUCH_UP;
    ltEvent = libinput_create_touch_event(touch, tEvent);
    funInputEvent_((libinput_event*)ltEvent, frameTime);
    free(ltEvent);

    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD;
    pEvent.delta_raw_x = VKEY_PINCH_CURSOR_FAKE_DX;
    pEvent.delta_raw_y = 0;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
}

bool LibinputAdapter::IsCursorInCastWindow()
{
    InputWindowsManager* inputWindowsManager = static_cast<InputWindowsManager *>(WIN_MGR.get());
    if (inputWindowsManager == nullptr) {
        return false;
    }
    DisplayGroupInfo displayGroupInfo = inputWindowsManager->GetDisplayGroupInfo();
    for (auto &windowInfo : displayGroupInfo.windowsInfo) {
        if (windowInfo.windowType == CAST_WINDOW_TYPE) {
            auto mouseInfo = WIN_MGR->GetMouseInfo();
            int32_t x = mouseInfo.physicalX;
            int32_t y = mouseInfo.physicalY;
            if ((x > windowInfo.area.x && x < (windowInfo.area.x + windowInfo.area.width)) &&
                (y > windowInfo.area.y && y < (windowInfo.area.y + windowInfo.area.height))) {
                return true;
            }
        }
    }

    return false;
}

bool LibinputAdapter::HandleVKeyTrackPadPanBegin(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    MMI_HILOGI("VKey TrackPad Pan Begin");
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_SCROLL_FINGER_BEGIN;
    pEvent.delta_x = msgPPosX;
    pEvent.delta_y = msgPPosY;
    pEvent.delta_raw_x = msgPPosX;
    pEvent.delta_raw_y = msgPPosY;
    pEvent.axes = VKEY_TP_AXES_ZERO;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadPanUpdate(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    MMI_HILOGI("VKey TrackPad Pan Update");
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_AXIS;
    pEvent.delta_x = msgPPosX;
    pEvent.delta_y = msgPPosY;
    pEvent.delta_raw_x = msgPPosX;
    pEvent.delta_raw_y = msgPPosY;
    pEvent.source = libinput_pointer_axis_source::LIBINPUT_POINTER_AXIS_SOURCE_FINGER;
    pEvent.axes = VKEY_TP_AXES_TWO;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_SCROLL_FINGER;
    lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadPanEnd(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    MMI_HILOGI("VKey TrackPad Pan End");
    event_pointer pEvent;
    pEvent.event_type = libinput_event_type::LIBINPUT_EVENT_POINTER_SCROLL_FINGER_END;
    pEvent.delta_x = msgPPosX;
    pEvent.delta_y = msgPPosY;
    pEvent.delta_raw_x = msgPPosX;
    pEvent.delta_raw_y = msgPPosY;
    pEvent.axes = VKEY_TP_AXES_ZERO;
    libinput_event_pointer* lpEvent = libinput_create_pointer_event(touch, pEvent);
    PrintVKeyTPPointerLog(pEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lpEvent, frameTime);
    free(lpEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadRotateBegin(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t msgPScale = msgItem[VKEY_TP_SM_MSG_SCALE_IDX];
    double scaleToDouble = static_cast<double>(msgPScale) / VTP_SCALE_AND_ANGLE_FACTOR;
    int32_t msgPAngle = msgItem[VKEY_TP_SM_MSG_ANGLE_IDX];
    double angleToDouble = static_cast<double>(msgPAngle) / VTP_SCALE_AND_ANGLE_FACTOR;
    MMI_HILOGI("VKey TrackPad Rotate Begin");
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_PINCH_BEGIN;
    gEvent.finger_count = VKEY_TP_GSE_TWO_FINGERS;
    gEvent.cancelled = 0;
    gEvent.delta_x = msgPPosX;
    gEvent.delta_y = msgPPosY;
    gEvent.delta_unaccel_x = msgPPosX;
    gEvent.delta_unaccel_y = msgPPosY;
    sloted_coords_info slotInfo;
    gEvent.solt_touches = slotInfo;
    gEvent.scale = scaleToDouble;
    gEvent.angle = angleToDouble;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    PrintVKeyTPGestureLog(gEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadRotateUpdate(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t msgPScale = msgItem[VKEY_TP_SM_MSG_SCALE_IDX];
    double scaleToDouble = static_cast<double>(msgPScale) / VTP_SCALE_AND_ANGLE_FACTOR;
    int32_t msgPAngle = msgItem[VKEY_TP_SM_MSG_ANGLE_IDX];
    double angleToDouble = static_cast<double>(msgPAngle) / VTP_SCALE_AND_ANGLE_FACTOR;
    MMI_HILOGI("VKey TrackPad Rotate Update");
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_PINCH_UPDATE;
    gEvent.finger_count = VKEY_TP_GSE_TWO_FINGERS;
    gEvent.cancelled = 0;
    gEvent.delta_x = msgPPosX;
    gEvent.delta_y = msgPPosY;
    gEvent.delta_unaccel_x = msgPPosX;
    gEvent.delta_unaccel_y = msgPPosY;
    sloted_coords_info slotInfo;
    gEvent.solt_touches = slotInfo;
    gEvent.scale = scaleToDouble;
    gEvent.angle = angleToDouble;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    PrintVKeyTPGestureLog(gEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
    return true;
}

bool LibinputAdapter::HandleVKeyTrackPadRotateEnd(libinput_event_touch* touch,
    const std::vector<int32_t>& msgItem)
{
    if (msgItem.size() < VKEY_TP_SM_MSG_SIZE) {
        MMI_HILOGE("Virtual TrackPad state machine message size:%{public}d is not correct",
            static_cast<int32_t>(msgItem.size()));
        return false;
    }
    int32_t msgPId = msgItem[VKEY_TP_SM_MSG_POINTER_ID_IDX];
    int32_t msgPPosX = msgItem[VKEY_TP_SM_MSG_POS_X_IDX];
    int32_t msgPPosY = msgItem[VKEY_TP_SM_MSG_POS_Y_IDX];
    int32_t msgPScale = msgItem[VKEY_TP_SM_MSG_SCALE_IDX];
    double scaleToDouble = static_cast<double>(msgPScale) / VTP_SCALE_AND_ANGLE_FACTOR;
    int32_t msgPAngle = msgItem[VKEY_TP_SM_MSG_ANGLE_IDX];
    double angleToDouble = static_cast<double>(msgPAngle) / VTP_SCALE_AND_ANGLE_FACTOR;
    MMI_HILOGI("VKey TrackPad Rotate End");
    event_gesture gEvent;
    gEvent.event_type = libinput_event_type::LIBINPUT_EVENT_GESTURE_PINCH_END;
    gEvent.finger_count = VKEY_TP_GSE_TWO_FINGERS;
    gEvent.cancelled = 0;
    gEvent.delta_x = msgPPosX;
    gEvent.delta_y = msgPPosY;
    gEvent.delta_unaccel_x = msgPPosX;
    gEvent.delta_unaccel_y = msgPPosY;
    sloted_coords_info slotInfo;
    gEvent.solt_touches = slotInfo;
    gEvent.scale = scaleToDouble;
    gEvent.angle = angleToDouble;
    libinput_event_gesture* lgEvent = libinput_create_gesture_event(touch, gEvent);
    PrintVKeyTPGestureLog(gEvent);
    int64_t frameTime = GetSysClockTime();
    funInputEvent_((libinput_event*)lgEvent, frameTime);
    free(lgEvent);
    return true;
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

void LibinputAdapter::PrintVKeyTPPointerLog(event_pointer &pEvent)
{
    MMI_HILOGD("######## pointerEvent");
    MMI_HILOGD("######## event type:%{public}d, delta.x:%{public}d, delta.y:%{public}d",
        static_cast<int32_t>(pEvent.event_type), static_cast<int32_t>(pEvent.delta_x),
        static_cast<int32_t>(pEvent.delta_y));
    MMI_HILOGD("######## delta_raw.x:%{public}d, delta_raw.y:%{public}d",
        static_cast<int32_t>(pEvent.delta_raw_x), static_cast<int32_t>(pEvent.delta_raw_y));
    MMI_HILOGD("######## absolute.x:%{public}d, absolute.y:%{public}d, source:%{public}d",
        static_cast<int32_t>(pEvent.absolute_x), static_cast<int32_t>(pEvent.absolute_y),
        static_cast<int32_t>(pEvent.source));
    MMI_HILOGD("######## axes:%{public}d, button:%{public}d, seat button count:%{public}d",
        static_cast<int32_t>(pEvent.axes), static_cast<int32_t>(pEvent.button),
        static_cast<int32_t>(pEvent.seat_button_count));
    MMI_HILOGD("######## state:%{public}d, discrete.x:%{public}d, discrete.y:%{public}d",
        static_cast<int32_t>(pEvent.state), static_cast<int32_t>(pEvent.discrete_x),
        static_cast<int32_t>(pEvent.discrete_y));
    MMI_HILOGD("######## v120.x:%{public}d, v120.y:%{public}d",
        static_cast<int32_t>(pEvent.v120_x), static_cast<int32_t>(pEvent.v120_y));
}

void LibinputAdapter::PrintVKeyTPGestureLog(event_gesture &gEvent)
{
    MMI_HILOGD("######## gestureEvent");
    MMI_HILOGD("######## event_type:%{public}d, finger_count:%{public}d, cancelled:%{public}d",
        static_cast<int32_t>(gEvent.event_type), static_cast<int32_t>(gEvent.finger_count),
        static_cast<int32_t>(gEvent.cancelled));
    MMI_HILOGD("######## delta_x:%{public}f, delta_y:%{public}f",
        static_cast<double>(gEvent.delta_x), static_cast<double>(gEvent.delta_y));
    MMI_HILOGD("######## delta_unaccel_x:%{public}f, delta_unaccel_y:%{public}f",
        static_cast<double>(gEvent.delta_unaccel_x), static_cast<double>(gEvent.delta_unaccel_y));
    MMI_HILOGD("######## solt_touches active_count:%{public}d",
        static_cast<int32_t>(gEvent.solt_touches.active_count));
    MMI_HILOGD("######## scale:%{public}f, angle:%{public}f",
        static_cast<double>(gEvent.scale), static_cast<double>(gEvent.angle));
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

void LibinputAdapter::ShowMouseCursor()
{
    MMI_HILOGD("Check cursor state function valid = %{public}d",
        IPointerDrawingManager::GetInstance() != nullptr);
    if (IPointerDrawingManager::GetInstance() != nullptr &&
        !IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
        MMI_HILOGI("Found hidden mouse cursor during trackpad operation, show it.");
        IPointerDrawingManager::GetInstance()->SetMouseDisplayState(true);
    }
}

void LibinputAdapter::HideMouseCursorTemporary()
{
    MMI_HILOGI("VKeyboard hide mouse.");
    if (IPointerDrawingManager::GetInstance() != nullptr &&
        IPointerDrawingManager::GetInstance()->GetMouseDisplayState()) {
        IPointerDrawingManager::GetInstance()->SetMouseDisplayState(false);
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
                MMI_HILOGI("activation state: %{public}d", static_cast<int32_t>(activateState));
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
                MMI_HILOGI("activation state: %{public}d, dropping event", static_cast<int32_t>(activateState));
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
    if (!isBootCompleted_ && isVKeyboardShown_ != nullptr) {
        isBootCompleted_ = isVKeyboardShown_();
        if (isBootCompleted_) {
            MMI_HILOGI("backend booted from outside (mainly due to process restart)=%{public}d",
                static_cast<int32_t>(isBootCompleted_));
        }
    }
    // could also check SA status here.
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

void LibinputAdapter::MultiKeyboardSetLedState(bool oldCapsLockState)
{
    std::vector<struct libinput_device*> input_device;
    INPUT_DEV_MGR->GetMultiKeyboardDevice(input_device);
    for (auto it = input_device.begin(); it != input_device.end(); ++it) {
        auto setDevice = (*it);
        CHKPV(setDevice);
        DeviceLedUpdate(setDevice, KeyEvent::CAPS_LOCK_FUNCTION_KEY, !oldCapsLockState);
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
                MultiKeyboardSetLedState(oldCapsLockOn);
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
        libinput_event_type eventType = libinput_event_get_type(event);
        int32_t touchId = 0;
        libinput_event_touch* touch = nullptr;
        static int32_t downCount = 0;

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

            if (handleTouchPoint_ != nullptr &&
                handleTouchPoint_(x, y, touchId, touchEventType, accumulatedPressure) == 0) {
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

            if (libinput_event_keyboard_get_key_state(keyboardEvent) == LIBINPUT_KEY_STATE_PRESSED
			   && libinput_event_keyboard_get_key(keyboardEvent) == KEY_CAPSLOCK
			   && keyEvent != nullptr) {
                bool oldCapsLockOn = keyEvent->GetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY);
                libinput_device* device = libinput_event_get_device(event);
                int libinputCaps = libinput_get_funckey_state(device, MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY);

                HandleHWKeyEventForVKeyboard(event);
                funInputEvent_(event, frameTime);
                libinput_event_destroy(event);

                MultiKeyboardSetLedState(oldCapsLockOn);
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
        MMI_HILOGI("OnDeviceAdded, path:%{public}s", path.c_str());
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
