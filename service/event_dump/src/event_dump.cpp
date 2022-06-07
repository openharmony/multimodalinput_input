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

#include "event_dump.h"

#include <climits>
#include <cstdarg>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "input_windows_manager.h"
#include "util.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDump" };
} // namespace

void ChkConfig(int32_t fd)
{
    mprintf(fd, "ChkMMIConfig: ");
#ifdef OHOS_BUILD
    mprintf(fd, "OHOS_BUILD");
#endif
#ifdef OHOS_BUILD_LIBINPUT
    mprintf(fd, "OHOS_BUILD_LIBINPUT");
#endif
#ifdef OHOS_BUILD_HDF
    mprintf(fd, "OHOS_BUILD_HDF");
#endif
#ifdef OHOS_BUILD_MMI_DEBUG
    mprintf(fd, "OHOS_BUILD_MMI_DEBUG");
#endif // OHOS_BUILD_MMI_DEBUG

    mprintf(fd, "DEF_MMI_DATA_ROOT: %s\n", DEF_MMI_DATA_ROOT);
    mprintf(fd, "EXP_CONFIG: %s\n", DEF_EXP_CONFIG);
    mprintf(fd, "EXP_SOPATH: %s\n", DEF_EXP_SOPATH);
}

bool EventDump::DumpEventHelp(int32_t fd, const std::vector<std::u16string> &args)
{
    if ((args.empty()) || (args[0].compare(u"-h") != 0)) {
        MMI_HILOGE("args cannot be empty or invalid");
        return false;
    }
    DumpHelp(fd);
    return true;
}

void EventDump::DumpHelp(int32_t fd)
{
    mprintf(fd, "Usage:\n");
    mprintf(fd, "      -h: dump help\n");
    mprintf(fd, "      -d: dump the device information\n");
    mprintf(fd, "      -w: dump the windows information \n");
	mprintf(fd, "      -u: dump the uds_server information \n");
    mprintf(fd, "      -o: dump the monitor information\n");
    mprintf(fd, "      -s: dump the subscriber information\n");
    mprintf(fd, "      -i: dump the interceptor information\n");
    mprintf(fd, "      -m: dump the mouse information\n");
}

void EventDump::Init(UDSServer& uds)
{
    udsServer_ = &uds;
}

void EventDump::InsertDumpInfo(const std::string& str)
{
    if (str.empty()) {
        MMI_HILOGE("The in parameter str is empty, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
    std::lock_guard<std::mutex> guard(mu_);

    static constexpr int32_t vecMaxSize = 300;
    if (dumpInfo_.size() > vecMaxSize) {
        dumpInfo_.erase(dumpInfo_.begin());
    }
    dumpInfo_.push_back(str);
}

void EventDump::InsertFormat(std::string str, ...)
{
    if (str.empty()) {
        MMI_HILOGE("The in parameter str is empty, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
    va_list args;
    va_start(args, str);
    char buf[MAX_PACKET_BUF_SIZE] = {};
    if (vsnprintf_s(buf, MAX_PACKET_BUF_SIZE, MAX_PACKET_BUF_SIZE - 1, str.c_str(), args) == -1) {
        MMI_HILOGE("vsnprintf_s error");
        va_end(args);
        return;
    }
    va_end(args);
    InsertDumpInfo(buf);
}
} // namespace MMI
} // namespace OHOS
