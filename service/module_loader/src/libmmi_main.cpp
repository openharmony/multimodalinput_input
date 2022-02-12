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

#include <sys/ioctl.h>
#include <inttypes.h>
#include "event_dump.h"
#include "input_device_manager.h"
#include "mmi_interface.h"
#include "mmi_server.h"
#include "safe_keeper.h"
#include "util.h"
#include "wayland-server-core.h"

#ifdef OHOS_BUILD_MMI_DEBUG
#include "command_helper.h"
#include "uds_command_queue.h"
#endif // OHOS_BUILD_MMI_DEBUG

namespace OHOS::MMI {
    namespace {
#ifdef OHOS_WESTEN_MODEL
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "libmmi_main" };
        static bool g_bThreadTerm = false;
#endif
    }
}


static std::atomic_bool g_isRun(false);

#ifdef DEBUG_CODE_TEST
static int64_t g_llStartTime = 0;
static std::atomic_bool g_isAllRun(false);

bool IsMmiServerWorking()
{
    return !!g_isAllRun;
}

void SetMmiServerWorking()
{
    g_isAllRun = true;
}

int64_t GetMmiServerStartTime()
{
    return g_llStartTime;
}
#endif // DEBUG_CODE_TEST

#ifdef OHOS_WESTEN_MODEL
namespace {
void OnThreadTermination(int32_t outTime, uint64_t tid, const std::string& remark)
{
    using namespace OHOS::MMI;
    MMI_LOGE("OnThreadTermination tid:%{public}" PRId64 " %{public}s %{public}d/%{public}d",
        tid, remark.c_str(), outTime, MAX_THREAD_DEATH_TIME);
    MMIEventDump->InsertFormat("OnThreadTermination tid=%llu, remark=%s %d/%d",
        tid, remark.c_str(), outTime, MAX_THREAD_DEATH_TIME);
    MMIEventDump->TestDump();
    MMIEventDump->Dump(-1);
    g_bThreadTerm = true;
}

void OnThread()
{
    using namespace OHOS::MMI;

    while (true) {
        g_bThreadTerm = false;
        SafeKpr->ClearAll();
#ifdef OHOS_WESTEN_MODEL
        OHOS::MMI::MMIServer mmiServer;
        SafeKpr->Init(std::bind(&OnThreadTermination, std::placeholders::_1, std::placeholders::_2,
            std::placeholders::_3));
        auto ret = mmiServer.Start();
        if (RET_OK != ret) {
            MMI_LOGW("MMIServer failed to start, it will restart in %{public}d milliseconds. ret:%{public}d",
                SERVER_RESTART_COOLING_TIME, ret);
            mmiServer.StopAll();
            std::this_thread::sleep_for(std::chrono::milliseconds(SERVER_RESTART_COOLING_TIME));
            continue;
        }
        while (g_isRun) {
            if (g_bThreadTerm) {
                MMI_LOGW("The program is abnormal(%{public}d), and the server will restart in %{public}d milliseconds",
                    g_bThreadTerm, SERVER_RESTART_COOLING_TIME);
                mmiServer.StopAll();
                std::this_thread::sleep_for(std::chrono::milliseconds(SERVER_RESTART_COOLING_TIME));
                break;
            }
            SafeKpr->ProcessEvents();
            mmiServer.OnTimer();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
#else
        std::this_thread::sleep_for(std::chrono::seconds(1));
#endif


        if (!g_isRun) {
            break;
        }
    }
#ifdef DEBUG_CODE_TEST
    g_isAllRun = false;
#endif
    MMI_LOGI("libmmi_main OnThread end...");
}
}
#endif

void Dump(int fd)
{
    MMIEventDump->Dump(fd);
}

int GetMultimodeInputinformation(void)
{
    if (!g_isRun) {
        return OHOS::MMI_SERVICE_INVALID;
    }
    return OHOS::MMI_SERVICE_RUNNING;
}

#ifdef OHOS_WESTEN_MODEL
void StartMmiServer(void)
{
#ifdef OHOS_BUILD_MMI_DEBUG
    VerifyLogManagerRun();
#endif

#ifdef DEBUG_CODE_TEST
    using namespace OHOS::MMI;
    uint64_t tid = OHOS::MMI::GetThisThreadIdOfLL();
    g_llStartTime = OHOS::MMI::GetMillisTime();
    MMI_LOGI("The server starts to start tid:%" PRId64 ". The current timestamp is %" PRId64
            " Ms", tid, g_llStartTime);
#endif
    g_isRun = true;
    static std::thread t(&OnThread);
    t.detach();
}
#endif
// weston启动入口函数
WL_EXPORT int wet_module_init(weston_compositor *ec, int *argc, char *argv[])
{
#ifdef OHOS_WESTEN_MODEL
    int socketPair[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, socketPair);
    MMIMsgPost.SetWestonCompositor(ec);

    wl_event_loop* loop = nullptr;
    uint32_t mask = 1;
    void *data = nullptr;
    loop = wl_display_get_event_loop(ec->wl_display);
    wl_event_loop_add_fd(loop, socketPair[1], mask, OHOS::MMI::MessagePost::RunTaskOnWestonThread, data);
    MMIMsgPost.SetFd(socketPair[0]);
    StartMmiServer();
#endif
    return RET_OK;
}
