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

#include "event_dump.h"

#include <getopt.h>

#include <climits>
#include <cstdarg>
#include <cstring>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "event_interceptor_handler.h"
#include "event_monitor_handler.h"
#include "i_pointer_drawing_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
#include "i_input_windows_manager.h"
#ifdef OHOS_BUILD_ENABLE_COMBINATION_KEY
#include "key_command_handler.h"
#endif // OHOS_BUILD_ENABLE_COMBINATION_KEY
#include "key_subscriber_handler.h"
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#include "mouse_event_normalize.h"
#include "switch_subscriber_handler.h"
#include "securec.h"
#include "touch_drawing_manager.h"
#include "util_ex.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventDump"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_COMMAND_COUNT { 32 };
} // namespace

EventDump::EventDump() {}
EventDump::~EventDump() {}

void ChkConfig(int32_t fd)
{
    mprintf(fd, "ChkMMIConfig: ");
    mprintf(fd, "DEF_MMI_DATA_ROOT:%s\n", DEF_MMI_DATA_ROOT);
    mprintf(fd, "EXP_CONFIG:%s\n", DEF_EXP_CONFIG);
    mprintf(fd, "EXP_SOPATH:%s\n", DEF_EXP_SOPATH);
}

void EventDump::CheckCount(int32_t fd, const std::vector<std::string> &args, int32_t &count)
{
    CALL_DEBUG_ENTER;
    for (const auto &str : args) {
        if (str.find("--") == 0) {
            ++count;
            continue;
        }
        if (str.find("-") == 0) {
            count += static_cast<int32_t>(str.size()) - 1;
            continue;
        }
    }
}

void EventDump::ParseCommand(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    int32_t count = 0;
    CheckCount(fd, args, count);
    if (count > MAX_COMMAND_COUNT) {
        MMI_HILOGE("cmd param number not more than 32");
        mprintf(fd, "cmd param number not more than 32\n");
        return;
    }
    int32_t optionIndex = 0;
    struct option dumpOptions[] = {
        { "help", no_argument, 0, 'h' },
        { "device", no_argument, 0, 'd' },
        { "devicelist", no_argument, 0, 'l' },
        { "windows", no_argument, 0, 'w' },
        { "udsserver", no_argument, 0, 'u' },
        { "subscriber", no_argument, 0, 's' },
        { "monitor", no_argument, 0, 'o' },
        { "interceptor", no_argument, 0, 'i' },
        { "filter", no_argument, 0, 'f' },
        { "mouse", no_argument, 0, 'm' },
        { "cursor", no_argument, 0, 'c' },
        { "keycommand", no_argument, 0, 'k' },
        { nullptr, 0, 0, 0 }
    };
    if (args.empty()) {
        MMI_HILOGE("size of args can't be zero");
        return;
    }
    char **argv = new (std::nothrow) char *[args.size()];
    CHKPV(argv);
    if (memset_s(argv, args.size() * sizeof(char*), 0, args.size() * sizeof(char*)) != EOK) {
        MMI_HILOGE("Call memset_s failed");
        delete[] argv;
        return;
    }
    for (size_t i = 0; i < args.size(); ++i) {
        argv[i] = new (std::nothrow) char[args[i].size() + 1];
        if (argv[i] == nullptr) {
            MMI_HILOGE("Failed to allocate memory");
            goto RELEASE_RES;
        }
        if (strcpy_s(argv[i], args[i].size() + 1, args[i].c_str()) != EOK) {
            MMI_HILOGE("strcpy_s error");
            goto RELEASE_RES;
        }
    }
    optind = 1;
    int32_t c;
    while ((c = getopt_long (args.size(), argv, "hdlwusoifmck", dumpOptions, &optionIndex)) != -1) {
        switch (c) {
            case 'h': {
                DumpEventHelp(fd, args);
                break;
            }
            case 'd': {
                INPUT_DEV_MGR->Dump(fd, args);
                break;
            }
            case 'l': {
                INPUT_DEV_MGR->DumpDeviceList(fd, args);
                break;
            }
            case 'w': {
                WIN_MGR->Dump(fd, args);
                break;
            }
            case 'u': {
                auto udsServer = InputHandler->GetUDSServer();
                CHKPV(udsServer);
                udsServer->Dump(fd, args);
                break;
            }
            case 's': {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
                auto subscriberHandler = InputHandler->GetSubscriberHandler();
                CHKPV(subscriberHandler);
                subscriberHandler->Dump(fd, args);
#else
                mprintf(fd, "Keyboard device does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD
                break;
            }
            case 'o': {
#ifdef OHOS_BUILD_ENABLE_MONITOR
                auto monitorHandler = InputHandler->GetMonitorHandler();
                CHKPV(monitorHandler);
                monitorHandler->Dump(fd, args);
#else
                mprintf(fd, "Monitor function does not support");
#endif // OHOS_BUILD_ENABLE_MONITOR
                break;
            }
            case 'i': {
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
                auto interceptorHandler = InputHandler->GetInterceptorHandler();
                CHKPV(interceptorHandler);
                interceptorHandler->Dump(fd, args);
#else
                mprintf(fd, "Interceptor function does not support");
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
                break;
            }
            case 'f': {
                auto filterHandler = InputHandler->GetFilterHandler();
                CHKPV(filterHandler);
                filterHandler->Dump(fd, args);
                break;
            }
            case 'm': {
#ifdef OHOS_BUILD_ENABLE_POINTER
                MouseEventHdr->Dump(fd, args);
#else
                mprintf(fd, "Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER
                break;
            }
            case 'c': {
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
                IPointerDrawingManager::GetInstance()->Dump(fd, args);
#else
                mprintf(fd, "Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_ENABLE_TOUCH
                TOUCH_DRAWING_MGR->Dump(fd, args);
#else
                mprintf(fd, "Pointer device does not support");
#endif // OHOS_BUILD_ENABLE_TOUCH
                break;
            }
            case 'k': {
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY)
                auto keyHandler = InputHandler->GetKeyCommandHandler();
                CHKPV(keyHandler);
                keyHandler->Dump(fd, args);
#else
                mprintf(fd, "Combination key does not support");
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_COMBINATION_KEY
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
        if (argv[i] != nullptr) {
            delete[] argv[i];
        }
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
    mprintf(fd, "      -h, --help: dump help\t");
    mprintf(fd, "      -d, --device: dump the device information\t");
    mprintf(fd, "      -l, --devicelist: dump the device list information\t");
    mprintf(fd, "      -w, --windows: dump the windows information\t");
    mprintf(fd, "      -u, --udsserver: dump the uds_server information\t");
    mprintf(fd, "      -o, --monitor: dump the monitor information\t");
    mprintf(fd, "      -s, --subscriber: dump the subscriber information\t");
    mprintf(fd, "      -i, --interceptor: dump the interceptor information\t");
    mprintf(fd, "      -f, --filter: dump the filter information\t");
    mprintf(fd, "      -m, --mouse: dump the mouse information\t");
    mprintf(fd, "      -c, --cursor: dump the cursor draw information\t");
    mprintf(fd, "      -k, --keycommand: dump the key command information\t");
}
} // namespace MMI
} // namespace OHOS
