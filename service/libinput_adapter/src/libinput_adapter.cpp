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

#include <cinttypes>
#include <climits>
#include <regex>

#include <dirent.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "define_multimodal.h"
#include "i_input_windows_manager.h"
#include "param_wrapper.h"
#include "util.h"
#include "input_device_manager.h"

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
                                    IsInsideVKeyboardArea isInsideVKeyboardArea,
                                    IsKeyboardVisible isKeyboardVisible,
                                    MapTouchToButton mapTouchToButton,
                                    KeyDown keyDown,
                                    KeyUp keyUp,
                                    GetMessage getMessage,
                                    GetKeyCodeByKeyName getKeyCodeByKeyName)
{
    handleTouchPoint_ = handleTouchPoint;
    isInsideVKeyboardArea_ = isInsideVKeyboardArea;
    isKeyboardVisible_ = isKeyboardVisible;
    mapTouchToButton_ = mapTouchToButton;
    keyDown_ = keyDown;
    keyUp_ = keyUp;
    getMessage_ = getMessage;
    getKeyCodeByKeyName_ = getKeyCodeByKeyName;

    deviceId = -1;
}

std::unordered_map<std::string, int32_t> LibinputAdapter::keyCodes_ = {
    { "Btn_ESCAPE", 1 }, { "Btn_F1", 59 }, { "Btn_F2", 60 }, { "Btn_F3", 61 }, { "Btn_F4", 62 },
    { "Btn_F5", 63 }, { "Btn_F6", 64 }, { "Btn_SMART", -1 }, { "Btn_F7", 65 }, { "Btn_F8", 66 },
    { "Btn_F9", 67 }, { "Btn_F10", 68 }, { "Btn_F11", 87 }, { "Btn_F12", 88 }, { "Btn_DELETE", 111 },

    { "Btn_OEM_3", 41 }, { "Btn_1", 2 }, { "Btn_2", 3 }, { "Btn_3", 4 }, { "Btn_4", 5 },
    { "Btn_5", 6 }, { "Btn_6", 7 }, { "Btn_7", 8 }, { "Btn_8", 9 }, { "Btn_9", 10 },
    { "Btn_0", 11 }, { "Btn_SS", 12 }, { "Btn_INVERTED_COMMA", 13 }, { "Btn_BACK", 14 },

    { "Btn_TAB", 15 }, { "Btn_Q", 16 }, { "Btn_W", 17 }, { "Btn_E", 18 }, { "Btn_R", 19 },
    { "Btn_T", 20 }, { "Btn_Y", 21 }, { "Btn_U", 22 }, { "Btn_I", 23 }, { "Btn_O", 24 },
    { "Btn_P", 25 }, { "Btn_UE", 26 }, { "Btn_PLUS", 27 }, { "Btn_HASHTAG", 43 },

    { "Btn_CAPS", 58 }, { "Btn_A", 30 }, { "Btn_S", 31 }, { "Btn_D", 32 }, { "Btn_F", 33 },
    { "Btn_G", 34 }, { "Btn_H", 35 }, { "Btn_J", 36 }, { "Btn_K", 37 }, { "Btn_L", 38 },
    { "Btn_OE", 39 }, { "Btn_AE", 40 }, { "Btn_ENTER", 28 },

    { "Btn_LSHIFT", 42 }, { "Btn_Z", 44 }, { "Btn_X", 45 }, { "Btn_C", 46 }, { "Btn_V", 47 },
    { "Btn_B", 48 }, { "Btn_N", 49 }, { "Btn_M", 50 }, { "Btn_COMMA", 51 }, { "Btn_DOT", 52 },
    { "Btn_MINUS", 53 }, { "Btn_RSHIFT", 54 },

    { "Btn_LCTRL", 29 }, { "Btn_FNCT", 125 }, { "Btn_WINDOWS", 86 }, { "Btn_ALT", 56 },
    { "Btn_SPACE", 57 }, { "Btn_ALTGR", 100 }, { "Btn_RCTRL", 97 }, { "Btn_LEFT", 105 },
    { "Btn_UP", 107 }, { "Btn_DOWN", 108 }, { "Btn_RIGHT", 106 },
};

void LibinputAdapter::InjectKeyEvent(libinput_event_touch* touch, int32_t keyCode,
                                     libinput_key_state state, int64_t frameTime)
{
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    libinput_event_keyboard* key_event_pressed =
            libinput_create_keyboard_event(touch, keyCode, state);

    funInputEvent_((libinput_event*)key_event_pressed, frameTime);
    free(key_event_pressed);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
}

void LibinputAdapter::InjectCombinationKeyEvent(libinput_event_touch* touch, std::vector<int32_t>& toggleKeyCodes,
                                                int32_t triggerKeyCode, int64_t frameTime)
{
    for (auto& toggleCode: toggleKeyCodes) {
        InjectKeyEvent(touch, toggleCode, libinput_key_state::LIBINPUT_KEY_STATE_PRESSED, frameTime);
    }
    InjectKeyEvent(touch, triggerKeyCode, libinput_key_state::LIBINPUT_KEY_STATE_PRESSED, frameTime);
    InjectKeyEvent(touch, triggerKeyCode, libinput_key_state::LIBINPUT_KEY_STATE_RELEASED, frameTime);
    for (auto& toggleCode: toggleKeyCodes) {
        InjectKeyEvent(touch, toggleCode, libinput_key_state::LIBINPUT_KEY_STATE_RELEASED, frameTime);
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
        if (eventType == LIBINPUT_EVENT_TOUCH_DOWN
            || eventType == LIBINPUT_EVENT_TOUCH_UP
            || eventType == LIBINPUT_EVENT_TOUCH_MOTION
            ) {

            libinput_event_touch* touch = libinput_event_get_touch_event(event);
            if (deviceId == -1) {
                // initialize touch device ID.
                libinput_device* device = libinput_event_get_device(event);
                deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
            }

            EventTouch touchInfo;
            int32_t logicalDisplayId = -1;
            double x = 0.0;
            double y = 0.0;
            int32_t touchId = libinput_event_touch_get_slot(touch);
            bool tipDown = (eventType != LIBINPUT_EVENT_TOUCH_UP);

            // touch up event has no coordinates information, skip coordinate calculation.
            if (eventType != LIBINPUT_EVENT_TOUCH_UP) {
                if (!WIN_MGR->TouchPointToDisplayPoint(deviceId, touch, touchInfo, logicalDisplayId)) {
                    MMI_HILOGE("Map touch point to display point failed");
                } else {
                    x = touchInfo.point.x;
                    y = touchInfo.point.y;

                    touchPoints_[touchId] = std::pair<double, double>(x, y);
                }
            } else {
                auto pos = touchPoints_.find(touchId);
                if (pos != touchPoints_.end()) {
                    x = (pos->second).first;
                    y = (pos->second).second;
                    touchPoints_.erase(pos);
                }
            }

            MMI_HILOGD("#### touch event. deviceId: %d, touchId: %d, x: %d, y: %d, type: %d", deviceId,
                       touchId, (int)x, (int)y, (int)eventType);

            if (handleTouchPoint_(x, y, touchId, tipDown) == 0) {
                MMI_HILOGD("#### inside vkeyboard area");

                while (true) {
                    std::string buttonName;
                    std::string toggleButtonName;
                    int buttonMode;
                    std::string restList;
                    VKeyboardMessageType type = (VKeyboardMessageType)getMessage_(buttonName, toggleButtonName,
                                                                                  buttonMode, restList);
                    MMI_HILOGD("#### get message type: %d", (int)type);
                    if (type == VNoMessage) {
                        break;
                    }

                    switch (type) {
                        case VKeyboardMessageType::VKeyPressed: {
                            MMI_HILOGD("#### press key: %s", buttonName.c_str());
                            int32_t keyCode = keyCodes_[buttonName];
                            InjectKeyEvent(touch, keyCode, libinput_key_state::LIBINPUT_KEY_STATE_PRESSED, frameTime);
                            InjectKeyEvent(touch, keyCode, libinput_key_state::LIBINPUT_KEY_STATE_RELEASED, frameTime);
                            break;
                        }
                        case VKeyboardMessageType::VCombinationKeyPressed: {
                            MMI_HILOGD("#### combination key. triger button: %s, toggle button: %s",
                                       buttonName.c_str(), toggleButtonName.c_str());

                            std::vector<int32_t> toggleKeyCodes;
                            std::string remainStr = toggleButtonName;
                            int32_t toggleCode(-1), triggerCode(-1);
                            while (remainStr.find(';') != std::string::npos) {
                                // still has more than one
                                size_t pos = remainStr.find(';');
                                toggleCode = keyCodes_[remainStr.substr(0, pos)];
                                if (toggleCode >= 0) {
                                    toggleKeyCodes.push_back(toggleCode);
                                }
                                remainStr = remainStr.substr(pos + 1);
                            }
                            // Add the last piece.
                            toggleCode = keyCodes_[remainStr];
                            if (toggleCode >= 0) {
                                toggleKeyCodes.push_back(toggleCode);
                            }
                            // Trigger code:
                            triggerCode = keyCodes_[buttonName];

                            InjectCombinationKeyEvent(touch, toggleKeyCodes, triggerCode, frameTime);
                            break;
                        }
                        default: break;
                    }
                }
                libinput_event_destroy(event);
            } else {
                funInputEvent_(event, frameTime);
                libinput_event_destroy(event);
            }
        } else {
            funInputEvent_(event, frameTime);
            libinput_event_destroy(event);
        }
#else // OHOS_BUILD_ENABLE_VKEYBOARD
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
    libinput_device* device = libinput_path_add_device(input_, path.c_str());
    if (device != nullptr) {
        devices_[std::move(path)] = libinput_device_ref(device);
        // Libinput doesn't signal device adding event in path mode. Process manually.
        OnEventHandler();
    }
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
