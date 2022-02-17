/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "s_input.h"
#include <climits>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <unistd.h>
#include "libmmi_util.h"
#include "safe_keeper.h"
#include "util.h"
#ifndef OHOS_WESTEN_MODEL
#include "input_windows_manager.h"
#endif
namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SInput" };
    }

static void HiLogFunc(struct libinput* input, enum libinput_log_priority priority, const char* fmt, va_list args)
{
    char buffer[256];
    (void)vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, fmt, args);
    MMI_LOGE("PrintLog_Info:%{public}s", buffer);
    va_end(args);
}

static void InitHiLogFunc(struct libinput* input)
{
    static bool initFlag = false;
    if (initFlag) {
        return;
    }
    libinput_log_set_handler(input, &OHOS::MMI::HiLogFunc);
    initFlag = true;
}
} // namespace MMI
} // namespace OHOS

void OHOS::MMI::SInput::LoginfoPackagingTool(libinput_event *event)
{
    CHKPV(event);
    auto context = libinput_event_get_context(event);
    InitHiLogFunc(context);
}

const static libinput_interface LIBINPUT_INTERFACE = {
    .open_restricted = [](const char *path, int32_t flags, void *user_data)->int32_t {
        using namespace OHOS::MMI;
        CHKPR(path, errno);
        char realPath[PATH_MAX] = {};
        if (realpath(path, realPath) == nullptr) {
            MMI_LOGE("path is error, path:%{public}s", path);
            return RET_ERR;
        }
        int32_t fd = open(realPath, flags);
        MMI_LOGD("libinput .open_restricted path:%{public}s,fd:%{public}d", path, fd);
        return fd < 0 ? -errno : fd;
    },
    .close_restricted = [](int32_t fd, void *user_data)
    {
        using namespace OHOS::MMI;
        MMI_LOGI("libinput .close_restricted fd:%{public}d", fd);
        close(fd);
    },
};

OHOS::MMI::SInput::SInput()
{
}

OHOS::MMI::SInput::~SInput()
{
}

bool OHOS::MMI::SInput::Init(FunInputEvent funInputEvent, const std::string& seat_id)
{
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
    auto rt = libinput_udev_assign_seat(input_, seat_id_.c_str());
    if (rt != 0) {
        libinput_unref(input_);
        udev_unref(udev_);
        return false;
    }
    lfd_ = libinput_get_fd(input_);
    if (lfd_ < 0) {
        libinput_unref(input_);
        udev_unref(udev_);
        lfd_ = -1;
        return false;
    }
    return true;
}

void OHOS::MMI::SInput::EventDispatch(epoll_event& ev)
{
    CHKPV(ev.data.ptr);
    auto fd = *static_cast<int*>(ev.data.ptr);
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_LOGF("SInput::OnEventDispatch epoll unrecoverable error,"
            "The service must be restarted. fd:%{public}d", fd);
        free(ev.data.ptr);
        ev.data.ptr = nullptr;
        return;
    }
    if (libinput_dispatch(input_) != 0) {
        MMI_LOGE("libinput: Failed to dispatch libinput");
        return;
    }
    OnEventHandler();
}

void OHOS::MMI::SInput::Stop()
{
    if (lfd_ >= 0) {
        close(lfd_);
        lfd_ = -1;
    }
    libinput_unref(input_);
    udev_unref(udev_);
}

void OHOS::MMI::SInput::OnEventHandler()
{
    CHKPV(funInputEvent_);
#ifndef OHOS_WESTEN_MODEL
    multimodal_libinput_event ev = { nullptr, nullptr };
    while ((ev.event = libinput_get_event(input_))) {
        funInputEvent_(&ev);
        libinput_event_destroy(ev.event);
    }
#endif
}
