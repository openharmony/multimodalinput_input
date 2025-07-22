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

#include "libinput_wrapper.h"

#include <cinttypes>
#include <climits>
#include <iostream>

#include <dirent.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "define_multimodal.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LibinputWrapper"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t WAIT_TIME_FOR_INPUT { 10 };
constexpr int32_t MAX_RETRY_COUNT { 5 };
} // namespace

LibinputWrapper::~LibinputWrapper()
{
    if (input_ != nullptr) {
        libinput_unref(input_);
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
        int32_t fd = -1;
        for (int32_t i = 0; i < MAX_RETRY_COUNT; i++) {
            fd = open(realPath, flags);
            if (fd >= 0) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_INPUT));
        }
        int32_t errNo = errno;
        MMI_HILOGWK("Libinput .open_restricted path:%{private}s,fd:%{public}d,errno:%{public}d", path, fd, errNo);
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

bool LibinputWrapper::Init()
{
    input_ = libinput_path_create_context(&LIBINPUT_INTERFACE, nullptr);
    CHKPF(input_);
    fd_ = libinput_get_fd(input_);
    if (fd_ < 0) {
        libinput_unref(input_);
        fd_ = -1;
        return false;
    }
    return true;
}

struct libinput_event* LibinputWrapper::Dispatch()
{
    CHKPP(input_);
    if (libinput_dispatch(input_) != 0) {
        std::cout << "Failed to dispatch input event" << std::endl;
        return nullptr;
    }
    return libinput_get_event(input_);
}

void LibinputWrapper::DrainEvents()
{
    CHKPV(input_);
    struct libinput_event *event;

    libinput_dispatch(input_);
    while ((event = libinput_get_event(input_))) {
        libinput_event_destroy(event);
        libinput_dispatch(input_);
    }
}

bool LibinputWrapper::AddPath(const std::string &path)
{
    CHKPF(input_);
    auto pos = devices_.find(path);
    if (pos != devices_.end()) {
        return true;
    }
    libinput_device* device = libinput_path_add_device(input_, path.c_str());
    CHKPF(device);
    devices_[std::move(path)] = libinput_device_ref(device);
    return true;
}

void LibinputWrapper::RemovePath(const std::string &path)
{
    CHKPV(input_);
    auto pos = devices_.find(path);
    if (pos != devices_.end()) {
        libinput_path_remove_device(pos->second);
        libinput_device_unref(pos->second);
        devices_.erase(pos);
    }
}
} // namespace MMI
} // namespace OHOS
