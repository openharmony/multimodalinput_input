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

#include <getopt.h>

#include <climits>
#include <cstdarg>
#include <cstring>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_handler_manager_global.h"
#include "input_windows_manager.h"
#include "interceptor_handler_global.h"
#include "key_event_subscriber.h"
#include "mouse_event_handler.h"
#include "securec.h"
#include "uds_server.h"
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

void EventDump::ParseCommand(int32_t fd, const std::vector<std::string> &args)
{
    CALL_LOG_ENTER;
    int32_t optionIndex = 0;
    struct option dumpOptions[] = {
        {"help", no_argument, 0, 'h'},
        {"device", no_argument, 0, 'd'},
        {"devicelist", no_argument, 0, 'l'},
        {"windows", no_argument, 0, 'w'},
        {"udsserver", no_argument, 0, 'u'},
        {"subscriber", no_argument, 0, 's'},
        {"monitor", no_argument, 0, 'o'},
        {"interceptor", no_argument, 0, 'i'},
        {"mouse", no_argument, 0, 'm'},
        {NULL, 0, 0, 0}
    };
    char **argv = new char *[args.size()];
    for (size_t i = 0; i < args.size(); ++i) {
        argv[i] = new char[args[i].size() + 1];
        if (strcpy_s(argv[i], args[i].size() + 1, args[i].c_str()) != EOK) {
            MMI_HILOGE("strcpy_s error");
            goto RELEASE_RES;
            return;
        }
    }
    optind = 1;
    int32_t c;
    while ((c = getopt_long (args.size(), argv, "hdlwusoim", dumpOptions, &optionIndex)) != -1) {
        switch (c) {
            case 'h': {
                DumpEventHelp(fd, args);
                break;
            }
            case 'd': {
                InputDevMgr->Dump(fd, args);
                break;
            }
            case 'l': {
                InputDevMgr->DumpDeviceList(fd, args);
                break;
            }
            case 'w': {
                WinMgr->Dump(fd, args);
                break;
            }
            case 'u': {
                auto udsServer = InputHandler->GetUDSServer();
                udsServer->Dump(fd, args);
                break;
            }
            case 's': {
                KeyEventSubscriber_.Dump(fd, args);
                break;
            }
            case 'o': {
                InputHandlerManagerGlobal::GetInstance().Dump(fd, args);
                break;
            }
            case 'i': {
                InterceptorHandlerGlobal::GetInstance()->Dump(fd, args);
                break;
            }
            case 'm': {
                MouseEventHdr->Dump(fd, args);
                break;
            }
            default: {
                mprintf(fd, "cmd param is error\n");
                DumpHelp(fd);
                break;
            }
        }
    }
    RELEASE_RES:
    for (size_t i = 0; i < args.size(); ++i) {
        delete[] argv[i];
    }
    delete[] argv;
}

void EventDump::DumpEventHelp(int32_t fd, const std::vector<std::string> &args)
{
    DumpHelp(fd);
}

void EventDump::DumpHelp(int32_t fd)
{
    mprintf(fd, "Usage:\t");
    mprintf(fd, "      -h: dump help\t");
    mprintf(fd, "      -d: dump the device information\t");
    mprintf(fd, "      -l: dump the device list information\t");
    mprintf(fd, "      -w: dump the windows information\t");
    mprintf(fd, "      -u: dump the uds_server information\t");
    mprintf(fd, "      -o: dump the monitor information\t");
    mprintf(fd, "      -s: dump the subscriber information\t");
    mprintf(fd, "      -i: dump the interceptor information\t");
    mprintf(fd, "      -m: dump the mouse information\t");
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
