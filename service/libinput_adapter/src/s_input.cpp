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
#include <sys/epoll.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include "libmmi_util.h"
#include "safe_keeper.h"
#include "util.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SInput" };
    }
}

const static libinput_interface LIBINPUT_INTERFACE = {
    .open_restricted = [](const char *path, int32_t flags, void *user_data)->int32_t {
        using namespace OHOS::MMI;
        CHKR(path, OHOS::NULL_POINTER, -errno);
        int32_t fd = open(path, flags);
        MMI_LOGD("libinput .open_restricted path:%{public}s fd:%{public}d", path, fd);
        return fd < 0 ? -errno : fd;
    },
    .close_restricted = [](int32_t fd, void *user_data)
    {
        using namespace OHOS::MMI;
        MMI_LOGI("libinput .close_restricted fd:%d\n", fd);
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
    EventDispatch();
    return true;
}

bool OHOS::MMI::SInput::Start()
{
    lfd_ = libinput_get_fd(input_);
    CHKF(lfd_ >= 0, VAL_NOT_EXP);
    isrun_ = true;
    t_ = std::thread(std::bind(&SInput::OnThread, this));
    t_.detach();
    return true;
}

void OHOS::MMI::SInput::Stop()
{
    isrun_ = false;

    if (lfd_ >= 0) {
        close(lfd_);
        lfd_ = -1;
    }
    if (t_.joinable()) {
        t_.join();
    }

    libinput_unref(input_);
    udev_unref(udev_);
}

void OHOS::MMI::SInput::OnEventHandler()
{
    CHK(funInputEvent_, NULL_POINTER);
    struct libinput_event *event = nullptr;
    while ((event = libinput_get_event(input_))) {
        funInputEvent_(event);
        libinput_event_destroy(event);
    }
}

void OHOS::MMI::SInput::EventDispatch()
{
    if (libinput_dispatch(input_) != 0) {
        MMI_LOGE("libinput: Failed to dispatch libinput");
        return;
    }
    OnEventHandler();
}

void OHOS::MMI::SInput::OnThread()
{
    OHOS::MMI::SetThreadName(std::string("s_input"));
    uint64_t tid = GetThisThreadIdOfLL();
    CHK(tid > 0, PARAM_INPUT_INVALID);
    MMI_LOGI("CInput::OnThread begin... fd:%{public}d tid:%{public}" PRId64 "", lfd_, tid);
    SafeKpr->RegisterEvent(tid, "CInput::_OnThread");

    int32_t count = 0;
    epoll_event vevt[10] = {};
    while (isrun_) {
        count = epoll_wait(lfd_, vevt, sizeof(vevt) / sizeof(vevt[0]), DEFINE_EPOLL_TIMEOUT);
        for (auto i = 0; i < count; i++) {
            EventDispatch();
        }
        SafeKpr->ReportHealthStatus(tid);
    }
    MMI_LOGI("SInput::OnThread end...\n");
}
