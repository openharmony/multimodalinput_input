/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "libinput_adapter.h"
#include <climits>
#include <cinttypes>
#include <dirent.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "define_multimodal.h"
#include "input_windows_manager.h"
#include "util.h"


namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "LibinputAdapter" };
constexpr int32_t WAIT_TIME_FOR_INPUT { 10 };
} // namespace

static void HiLogFunc(struct libinput* input, libinput_log_priority priority, const char* fmt, va_list args)
{
    CHKPV(input);
    char buffer[256];
    if (vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, fmt, args) == -1) {
        MMI_HILOGE("Call vsnprintf_s failed");
        va_end(args);
        return;
    }
    MMI_HILOGE("PrintLog_Info:%{public}s", buffer);
    va_end(args);
}

static void InitHiLogFunc(struct libinput* input)
{
    CHKPV(input);
    static bool initFlag = false;
    if (initFlag) {
        return;
    }
    libinput_log_set_handler(input, &HiLogFunc);
    initFlag = true;
}

void LibinputAdapter::LoginfoPackagingTool(struct libinput_event *event)
{
    CHKPV(event);
    auto context = libinput_event_get_context(event);
    CHKPV(context);
    InitHiLogFunc(context);
}

int32_t LibinputAdapter::DeviceLedUpdate(struct libinput_device *device, int32_t funcKey, bool enable)
{
    CHKPR(device, RET_ERR);
    return libinput_set_led_state(device, funcKey, enable);
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
        int32_t fd = open(realPath, flags);
        int32_t errNo = errno;
        MMI_HILOGWK("Libinput .open_restricted path:%{public}s,fd:%{public}d,errno:%{public}d", path, fd, errNo);
        return fd < 0 ? RET_ERR : fd;
    },
    .close_restricted = [](int32_t fd, void *user_data)
    {
        MMI_HILOGI("Libinput .close_restricted fd:%{public}d", fd);
        close(fd);
    },
};

LibinputAdapter::LibinputAdapter() {}

LibinputAdapter::~LibinputAdapter() {}

bool LibinputAdapter::Init(FunInputEvent funInputEvent, const std::string& seat_id)
{
    CALL_DEBUG_ENTER;
    CHKPF(funInputEvent);
    funInputEvent_ = funInputEvent;
    seat_id_ = seat_id;
    if (seat_id_.empty()) {
        seat_id_ = DEF_SEAT_ID;
    }
    udev_ = udev_new();
    CHKPF(udev_);
    input_ = libinput_udev_create_context(&LIBINPUT_INTERFACE, nullptr, udev_);
    CHKPF(input_);
    int32_t rt = libinput_udev_assign_seat(input_, seat_id_.c_str());
    if (rt != 0) {
        libinput_unref(input_);
        udev_unref(udev_);
        MMI_HILOGE("The rt is not 0");
        return false;
    }
    fd_ = libinput_get_fd(input_);
    if (fd_ < 0) {
        libinput_unref(input_);
        udev_unref(udev_);
        fd_ = -1;
        MMI_HILOGE("The fd_ is less than 0");
        return false;
    }
    return true;
}

void LibinputAdapter::EventDispatch(struct epoll_event& ev)
{
    CALL_DEBUG_ENTER;
    CHKPV(ev.data.ptr);
    auto fd = *static_cast<int*>(ev.data.ptr);
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_HILOGF("Epoll unrecoverable error,"
            "The service must be restarted. fd:%{public}d", fd);
        free(ev.data.ptr);
        ev.data.ptr = nullptr;
        return;
    }
    if (libinput_dispatch(input_) != 0) {
        MMI_HILOGE("Failed to dispatch libinput");
        return;
    }
    OnEventHandler();
}

void LibinputAdapter::Stop()
{
    CALL_DEBUG_ENTER;
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    libinput_unref(input_);
    udev_unref(udev_);
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
    while ((event = libinput_get_event(input_))) {
        funInputEvent_(event);
        libinput_event_destroy(event);
    }
}

void LibinputAdapter::ReloadDevice()
{
    CALL_DEBUG_ENTER;
    CHKPV(input_);
    libinput_suspend(input_);
    libinput_resume(input_);
}

void LibinputAdapter::RetriggerHotplugEvents()
{
    CALL_INFO_TRACE;
    DIR *pdir = opendir("/sys/class/input");
    if (pdir == nullptr) {
        MMI_HILOGE("Failed to open directory: \'/sys/class/input\'");
        return;
    }
    for (struct dirent *pdirent = readdir(pdir); pdirent != nullptr; pdirent = readdir(pdir)) {
        char path[PATH_MAX];
        if (sprintf_s(path, sizeof(path), "/sys/class/input/%s/uevent", pdirent->d_name) < 0) {
            continue;
        }
        MMI_HILOGD("trigger \'%{public}s\'", path);
        FILE *fs = fopen(path, "r+");
        if (fs == nullptr) {
            continue;
        }
        if (fputs("add", fs) < 0) {
            MMI_HILOGW("fputs error:%{public}s", strerror(errno));
        }
        if (fclose(fs) != 0) {
            MMI_HILOGW("fclose error:%{public}s", strerror(errno));
        }
    }
    if (closedir(pdir) != 0) {
        MMI_HILOGW("closedir error:%{public}s", strerror(errno));
    }
}
} // namespace MMI
} // namespace OHOS
