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

#include "event_dump.h"
#include <climits>
#include <cstdarg>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "input_windows_manager.h"
#include "register_event.h"
#include "register_eventhandle_manager.h"
#include "util.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventDump" };
    }

void ChkConfig(int32_t fd)
{
    mprintf(fd, "ChkMMIConfig: ");
#ifdef OHOS_BUILD
    mprintf(fd, "\tOHOS_BUILD");
#endif
#ifdef OHOS_WESTEN_MODEL
    mprintf(fd, "\tOHOS_WESTEN_MODEL");
#endif
#ifdef OHOS_BUILD_LIBINPUT
    mprintf(fd, "\tOHOS_BUILD_LIBINPUT");
#endif
#ifdef OHOS_BUILD_HDF
    mprintf(fd, "\tOHOS_BUILD_HDF");
#endif
#ifdef OHOS_BUILD_AI
    mprintf(fd, "\tOHOS_BUILD_AI");
#endif
#ifdef DEBUG_CODE_TEST
    mprintf(fd, "\tDEBUG_CODE_TEST");
#endif
#ifdef OHOS_BUILD_MMI_DEBUG
    mprintf(fd, "\tOHOS_BUILD_MMI_DEBUG");
#endif // OHOS_BUILD_MMI_DEBUG

    mprintf(fd, "\tDEF_MMI_DATA_ROOT: %s\n", DEF_MMI_DATA_ROOT);
    mprintf(fd, "\tLOG_CONFIG: %s\n", DEF_LOG_CONFIG);
    mprintf(fd, "\tEXP_CONFIG: %s\n", DEF_EXP_CONFIG);
    mprintf(fd, "\tEXP_SOPATH: %s\n", DEF_EXP_SOPATH);
    mprintf(fd, "\tXKB_CONFIG_PATH: %s\n", DEF_XKB_CONFIG);
}

void ChkAppInfos(int32_t fd)
{
    auto focusId = WinMgr->GetFocusSurfaceId();
    auto touchFocusId = WinMgr->GetTouchFocusSurfaceId();
    auto appInfo = AppRegs->FindByWinId(focusId);
    mprintf(fd, "FocusInfo: winId=%d fd=%d abilityId=%d surfaceId=%d bundlerName=%s appName=%s",
            focusId, appInfo.fd, appInfo.abilityId, appInfo.windowId, appInfo.bundlerName.c_str(),
            appInfo.appName.c_str());
    if (focusId != touchFocusId) {
        appInfo = AppRegs->FindByWinId(touchFocusId);
        mprintf(fd, "TouchFocusInfo: winId=%d fd=%d abilityId=%d surfaceId=%d bundlerName=%s appName=%s",
                touchFocusId, appInfo.fd, appInfo.abilityId, appInfo.windowId, appInfo.bundlerName.c_str(),
                appInfo.appName.c_str());
    }
    AppRegs->Dump(fd);
}

void EventDump::Init(UDSServer& udss)
{
    udsServer_ = &udss;
}

void EventDump::Dump(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);

    auto strCurTime = Strftime();
    mprintf(fd, "MMIDumpsBegin: %s", strCurTime.c_str());
    ChkConfig(fd);
    ChkAppInfos(fd);
    WinMgr->Dump(fd);
    RegEventHM->Dump(fd);
    if (udsServer_) {
        udsServer_->Dump(fd);
    }

    // msgDumps
    mprintf(fd, "MMI_MSGDumps:");
    for (const auto &item : dumpInfo_) {
        mprintf(fd, "\t%s", item.c_str());
    }
    strCurTime = Strftime();
    mprintf(fd, "MMIDumpsEnd: %s", strCurTime.c_str());
}

void EventDump::TestDump()
{
    constexpr int32_t MAX_PATH_SIZE = 128;
    char szPath[MAX_PATH_SIZE] = {};
    CHK(sprintf_s(szPath, MAX_PATH_SIZE, "%s/mmidump-%s.txt", DEF_MMI_DATA_ROOT, Strftime("%y%m%d%H%M%S").c_str()) >= 0,
        SPRINTF_S_SEC_FUN_FAIL);
    char path[PATH_MAX] = {};
    if (realpath(szPath, path) == nullptr) {
        MMI_LOGE("path is error, szPath:%{public}s", szPath);
        return;
    }
    auto fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    CHK(fd >= 0, FILE_OPEN_FAIL);
    Dump(fd);
    close(fd);
}

void EventDump::InsertDumpInfo(const std::string& str)
{
    CHK(!str.empty(), PARAM_INPUT_INVALID);
    std::lock_guard<std::mutex> lock(mu_);

    const int32_t VECMAXSIZE = 300;
    while (dumpInfo_.size() > VECMAXSIZE) {
        dumpInfo_.erase(dumpInfo_.begin());
    }
    dumpInfo_.push_back(str);
}

void EventDump::InsertFormat(std::string str, ...)
{
    CHK(!str.empty(), INVALID_PARAM);
    va_list args;
    va_start(args, str);
    char buf[MAX_STREAM_BUF_SIZE] = {};
    if (vsnprintf_s(buf, MAX_STREAM_BUF_SIZE, MAX_STREAM_BUF_SIZE - 1, str.c_str(), args) == -1) {
        MMI_LOGE("InsertDumpInfo vsnprintf_s error");
        va_end(args);
        return;
    }
    va_end(args);
    InsertDumpInfo(buf);
}
}
}
