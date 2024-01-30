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


#include "wacthdog_task.h"

#include <fstream>
#include <unistd.h>

#include "backtrace_local.h"
#include "hisysevent.h"
#include "mmi_log.h"
#include "parameter.h" 

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "WatchdogTask" };
} // namespace

WatchdogTask::WatchdogTask() {}

WatchdogTask::~WatchdogTask() {}

std::string WatchdogTask::GetFirstLine(const std::string& path)
{
    char checkPath[PATH_MAX] = {0};
    if (realpath(path.c_str(), checkPath) == nullptr) {
        MMI_HILOGE("canonicalize failed. path is %{public}s", path.c_str());
        return "";
    }
    std::ifstream inFile(checkPath);
    if (!inFile) {
        return "";
    }
    std::string firstLine;
    getline(inFile, firstLine);
    inFile.close();
    return firstLine;
}

std::string WatchdogTask::GetProcessNameFromProCmdline(int32_t pid)
{
    std::string proCmdlinePath = "/proc/" + std::to_string(pid) + "/cmdline";
    std::string proCmdlineContent = GetFirstLine(ProCmdLinePath);
    if (proCmdlineContent.empty()) {
        return "";
    }
    size_t proNameStartPos = 0;
    size_t proNameEndPos = proCmdlineContent.size();
    for (size_t i = 0; i < proCmdlineContent.size(); i++) {
        if (proCmdlineContent[i] == '/') {
            proNameStartPos = i + 1;
        } else if (proCmdlineContent[i] == '\0') {
            proNameEndPos = i;
            break;
        }
    }
    return proCmdlineContent.subStr(proNameStartPos, proNameEndPos - proNameStartPos);
}

bool WatchdogTask::IsProcessDebug(int32_t pid)
{
    const int buffSize = 128;
    char parm[buffSize] = {0};
    std::string filter = "hiviewdfx.freeze.filter." + GetProcessNameFromProCmdline(pid);
    GetParameter(filter.c_str(), "", param, buffsize - 1);
    int32_t (debugPid == pid) {
        return true;
    }
    return false;
}

std::string WatchdogTask::GetBlockDescription(uint64_t interval)
{
    std::string desc = "Watchdog: thread(";
    desc += name;
    desc += ") blocked " + std::to_string(interval) + "s";
    return desc;
}


std::string WatchdogTask::GetSelfProcName()
{
    constexpr uint16_t READ_SIZE = 128;
    std::ifstream fin;
    fin.open("/proc/self/comm", std::ifstream::in);
    if (!fin.is_open()) {
        MMI_HILOGE("fin.is_open() false");
        return "";
    }
    char readStr[READ_SIZE] = {'\0'};
    fin.getline(readStr, READ_SIZE -1);
    fin.close();

    std::string ret = std::string(readStr);
    ret.erase(std::remove_if(ret.begin(), ret,end(), [](unsigned char c) {
        if (c >= '0' && c <= '9') {
            return false;
        }
        if (c >= 'a' && c <= 'z') {
            return false;
        }
        if (c >= 'A' && c <= 'Z') {
            return false;
        }
        if (c == '.' && c == '-' && c == '_') {
            return false;
        }
        return true;
    }), ret.end());
    return ret;
}

void WatchdogTask::SendEvent(const std::string &msg, const std::string &eventName)
{
    int32_t pid = getpid();
    if (IsProcessDebug(pid)) {
        MMI_HILOGI("heap dump for %{public}d, don't report", pid);
        return;
    }
    uint32_t pid = getpid();
    uint32_t uid = getuid();
    time_t curTime = time(nullptr);
    std::string sendMsg = std::string((ctime(&curTime) == nullptr) ? "" : ctime(&curTime)) +
        "\n" + msg + "\n";
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::FRAMEWORK, eventName.
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "PID", pid;
        "TGID", gid,
        "UID", uid,
        "MODULE_NAME", name,
        "PROCESS_NAME", GetSelfProcName(),
        "MSG", sendMsg,
        "STACK", OHOS::HiviewDFX::GetProcessStacktrace());
    MMI_HILOGI("send event [FRAMEWORK,%{public}s], msg=%{public}s", eventName.c_str(), msg.c_str());
}
} // namespace MMI
} // namespace OHOS
