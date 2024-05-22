/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "hotplug_detector.h"

#include <string>
#include <system_error>
#include <thread>

#include <dirent.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "HotplugDetector"

namespace OHOS {
namespace MMI {
namespace {
constexpr auto MAX_EVENT_BUF_SIZE = 512;
constexpr auto INPUT_DEVICES_PATH = "/dev/input/";

auto SystemError()
{
    return std::error_code{errno, std::system_category()};
}
} // namespace

HotplugDetector::HotplugDetector() = default;

HotplugDetector::~HotplugDetector() = default;

void HotplugDetector::Stop()
{
    CALL_DEBUG_ENTER;
    inotifyFd_ = {};
}

bool HotplugDetector::Init(const callback& addFunc, const callback& removeFunc)
{
    CALL_DEBUG_ENTER;
    if (!addFunc || !removeFunc) {
        return false;
    }
    addFunc_ = addFunc;
    removeFunc_ = removeFunc;

    auto fd = UniqueFd{inotify_init1(IN_CLOEXEC)};
    if (fd < 0) {
        MMI_HILOGE("Failed to initialize inotify. Error:%{public}s", SystemError().message().c_str());
        return false;
    }
    if (inotify_add_watch(fd, INPUT_DEVICES_PATH, IN_DELETE | IN_CREATE) < 0) {
        MMI_HILOGE("Failed to add watch for input devices. Error:%{public}s", SystemError().message().c_str());
        return false;
    }
    if (!Scan()) {
        return false;
    }
    inotifyFd_ = std::move(fd);
    return true;
}

bool HotplugDetector::Scan() const
{
    CALL_DEBUG_ENTER;
    using namespace std::literals::string_literals;
    auto* dir = opendir(INPUT_DEVICES_PATH);
    CHKPF(dir);
    dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name == "."s || entry->d_name == ".."s) {
            continue;
        }
        addFunc_(std::string{INPUT_DEVICES_PATH} + entry->d_name);
    }
    closedir(dir);
    return true;
}

void HotplugDetector::OnEvent() const
{
    constexpr int32_t EVSIZE = static_cast<int32_t>(sizeof(inotify_event));
    CALL_DEBUG_ENTER;
    if (inotifyFd_ < 0) {
        return;
    }
    std::byte event_buf[MAX_EVENT_BUF_SIZE];
    int32_t res = read(inotifyFd_, event_buf, sizeof(event_buf));
    if (res < EVSIZE) {
        auto err = SystemError();
        if (err != std::errc::resource_unavailable_try_again) {
            MMI_HILOGE("Filed to read inotify event. Error:%{public}s", err.message().c_str());
        }
        return;
    }
    inotify_event event;
    for (int32_t pos = 0; res > EVSIZE;) {
        std::copy_n(event_buf + pos, sizeof(event), reinterpret_cast<std::byte*>(&event));
        if (event.len != 0) {
            auto path = INPUT_DEVICES_PATH + std::string{reinterpret_cast<char*>(event_buf + pos + sizeof(event))};
            if (event.mask & IN_CREATE) {
                addFunc_(path);
            } else {
                removeFunc_(path);
            }
        }
        int32_t consumed = EVSIZE + event.len;
        pos += consumed;
        res -= consumed;
    }
}
} // namespace MMI
} // namespace OHOS
