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

#include <dirent.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "define_multimodal.h"
#include "i_input_windows_manager.h"
#include "param_wrapper.h"
#include "util.h"

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
    MMI_HILOGD("PrintLog_Info:%{public}s", buffer);
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
        MMI_HILOGWK("Libinput .open_restricted path:%{public}s,fd:%{public}d,errno:%{public}d", path, fd, errNo);
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

void LibinputAdapter::OnEventHandler()
{
    CALL_DEBUG_ENTER;
    CHKPV(funInputEvent_);
    libinput_event *event = nullptr;
    int64_t frameTime = GetSysClockTime();
    while ((event = libinput_get_event(input_))) {
        funInputEvent_(event, frameTime);
        libinput_event_destroy(event);
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
    CALL_DEBUG_ENTER;
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
    CALL_DEBUG_ENTER;
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
