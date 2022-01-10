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
namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SInput" };
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
}

void OHOS::MMI::SInput::Loginfo_packaging_tool(libinput_event& event)
{
    auto context = libinput_event_get_context(&event);
    InitHiLogFunc(context);
}

const static libinput_interface LIBINPUT_INTERFACE = {
    .open_restricted = [](const char *path, int32_t flags, void *user_data)->int32_t {
        using namespace OHOS::MMI;
        CHKR(path, OHOS::NULL_POINTER, -errno);
        char realPath[PATH_MAX] = {};
        if (realpath(path, realPath) == nullptr) {
            MMI_LOGE("path is error, path = %{public}s", path);
            return RET_ERR;
        }
        int32_t fd = open(realPath, flags);
        MMI_LOGD("libinput .open_restricted path:%{public}s fd:%{public}d", path, fd);
        return fd < 0 ? -errno : fd;
    },
    .close_restricted = [](int32_t fd, void *user_data)
    {
        using namespace OHOS::MMI;
        MMI_LOGI("libinput .close_restricted fd:%{public}d\n", fd);
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
    CHKF(funInputEvent, OHOS::NULL_POINTER);
    funInputEvent_ = funInputEvent;
    seat_id_ = seat_id;
    if (seat_id_.empty()) {
        seat_id_ = DEF_SEAT_ID;
    }
    udev_ = udev_new();
    CHKF(udev_, OHOS::NULL_POINTER);
    input_ = libinput_udev_create_context(&LIBINPUT_INTERFACE, nullptr, udev_);
    CHKF(input_, OHOS::NULL_POINTER);
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
    CHK(ev.data.ptr, NULL_POINTER);
    auto fd = *static_cast<int*>(ev.data.ptr);
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_LOGF("SInput::OnEventDispatch epoll unrecoverable error, "
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
    CHK(funInputEvent_, NULL_POINTER);
#ifndef OHOS_WESTEN_MODEL
    struct multimodal_libinput_event ev = { nullptr, nullptr };
    while ((ev.event = libinput_get_event(input_))) {
        /* remove these code when power key feature is up. start */
        HandlePowerKey(ev.event);
        /* remove these code when power key feature is up. end */
        funInputEvent_(&ev);
        libinput_event_destroy(ev.event);
    }
#endif
}

/* remove these code when power key feature is up. start */
void OHOS::MMI::SInput::WriteBrightness(const char *brightness)
{
    int fd = open("/sys/class/leds/lcd_backlight0/brightness", O_WRONLY);
    int ret = write(fd, brightness, strlen(brightness));
    MMI_LOGI("power key write brightness %{public}s, %{public}d", brightness, ret);
    close(fd);
}

bool OHOS::MMI::SInput::HandlePowerKey(struct libinput_event *event)
{
    bool isKeyboardEvent = (libinput_event_get_type(event) == LIBINPUT_EVENT_KEYBOARD_KEY);
    if (!isKeyboardEvent) {
        return (screenState_ == 0);
    }

    uint32_t KEY_POWER = 116;
    struct libinput_event_keyboard *keyboardEvent = libinput_event_get_keyboard_event(event);
    uint32_t keyCode = libinput_event_keyboard_get_key(keyboardEvent);
    uint32_t keyAction = libinput_event_keyboard_get_key_state(keyboardEvent);

    if ((keyCode != KEY_POWER) || keyAction != LIBINPUT_KEY_STATE_RELEASED) {
        return false;
    }
    MMI_LOGI("power key handle key %{public}u, %{public}u", keyCode, keyAction);

    const char *brightness = "2000";
    if (screenState_ == -1) {
        // init brightness node
        WriteBrightness(brightness);
        screenState_ = 1;
    }

    if (screenState_ == 1) {
        // screen backlight off
        brightness = "0000";
        screenState_ = 0;
    } else {
        // screen backlight on
        screenState_ = 1;
    }
    WriteBrightness(brightness);
    return false;
}
/* remove these code when power key feature is up. end */
