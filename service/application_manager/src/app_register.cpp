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
#include "app_register.h"
#include "util_ex.h"
#include "mmi_server.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "AppRegister" };
    }
#if 0
constexpr int32_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
constexpr int32_t INPUT_NUI_TIMEOUT_TIME = 10 * 1000000;
constexpr int32_t WAIT_QUEUE_EVENTS_MAX = 128;
#endif
AppRegister::AppRegister() {}

AppRegister::~AppRegister() {}

bool AppRegister::Init(UDSServer& udsServer)
{
    surfaceInfo_.clear();
    waitQueue_.clear();
    connectState_.clear();
    if (mu_.try_lock()) {
        mu_.unlock();
    }
    udsServer_ = &udsServer;
    return true;
}

const AppInfo& AppRegister::FindWinId(int32_t windowId)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = surfaceInfo_.find(windowId);
    if (it != surfaceInfo_.end()) {
        return it->second;
    }
    return AppRegister::appInfoError_;
}

const AppInfo& AppRegister::FindSocketFd(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    CHKR(fd >= 0, PARAM_INPUT_INVALID, appInfoError_);
    for (const auto &item : surfaceInfo_) {
        if (item.second.fd == fd) {
            return item.second;
        }
    }
    return AppRegister::appInfoError_;
}

void AppRegister::RegisterAppInfoforServer(const AppInfo& appInfo)
{
    std::lock_guard<std::mutex> lock(mu_);
    surfaceInfo_.insert(std::pair<int32_t, AppInfo>(appInfo.windowId, appInfo));
    AddId(fds_, appInfo.fd);
}

void AppRegister::UnregisterAppInfoSocketFd(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    UnregisterSocketFd(fd);
}

void AppRegister::UnregisterSocketFd(int32_t fd)
{
    auto it = surfaceInfo_.begin();
    while (it != surfaceInfo_.end()) {
        if (it->second.fd == fd) {
            it = surfaceInfo_.erase(it);
        } else {
            ++it;
        }
    }
}

std::map<int32_t, AppInfo>::iterator AppRegister::EraseAppInfo(const std::map<int32_t, AppInfo>::iterator &it)
{
    return surfaceInfo_.erase(it);
}

std::map<int32_t, AppInfo>::iterator AppRegister::UnregisterAppInfo(int32_t winId)
{
    if (winId <= 0) {
        MMI_LOGE("Parameter is invalid, Unregister failed");
        return surfaceInfo_.end();
    }
    auto itr = surfaceInfo_.find(winId);
    if (itr == surfaceInfo_.end()) {
        MMI_LOGE("Window(%{public}d) not found, Unregister failed", winId);
        return surfaceInfo_.end();
    }
    return EraseAppInfo(itr);
}

void AppRegister::PrintfMap()
{
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto &item : surfaceInfo_) {
        std::cout << "mapSurface " << item.second.abilityId << ", " << item.second.windowId <<
            ", " << item.second.fd << std::endl;
    }
}

void OHOS::MMI::AppRegister::Dump(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    mprintf(fd, "AppInfos: count=%d", surfaceInfo_.size());
    for (const auto &item : surfaceInfo_) {
        mprintf(fd, "\tabilityId=%d windowId=%d fd=%d bundlerName=%s appName=%s", item.second.abilityId,
                item.second.windowId, item.second.fd, item.second.bundlerName.c_str(), item.second.appName.c_str());
    }
}

void AppRegister::SurfacesDestroyed(const std::vector<int32_t> &desList)
{
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto &item : desList) {
        UnregisterAppInfo(item);
    }
}

int32_t AppRegister::QueryMapSurfaceNum()
{
    std::lock_guard<std::mutex> lock(mu_);
    return static_cast<int32_t>(surfaceInfo_.size());
}

bool AppRegister::IsMultimodeInputReady(MmiMessageId idMsg, const int32_t findFd, int64_t inputTime,
                                        int64_t westonTime)
{
#if 0 // temp comment for test
    std::lock_guard<std::mutex> lock(mu_);
    auto serverTime = GetSysClockTime();
    WaitQueueEvent newEvent = {findFd, static_cast<int32_t>(idMsg), inputTime, westonTime, serverTime};

    ssize_t timeOut = INPUT_NUI_TIMEOUT_TIME;
    if ((idMsg == MmiMessageId::ON_KEY) || (idMsg == MmiMessageId::ON_TOUCH)) {
        timeOut = INPUT_UI_TIMEOUT_TIME;
    }

    if (!CheckFindFdError(findFd)) {
        OnAnrLocked(findFd);
        return false;
    }
    if (!CheckWaitQueueBlock(serverTime, timeOut, findFd)) {
        OnAnrLocked(findFd);
        return false;
    }

    if (waitQueue_.size() > WAIT_QUEUE_EVENTS_MAX) {
        waitQueue_.clear();
        MMI_LOGD("IsMultimodeInputReady The Wait Queue is full! Clear it!");
    }
    waitQueue_.push_back(newEvent);
#endif
    return true;
}

WaitQueueEvent AppRegister::GetWaitQueueEvent(int32_t fd, int32_t idMsg)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto find_fun = [fd, idMsg](const WaitQueueEvent &ev) -> bool {
        if (fd != ev.fd || idMsg != ev.event) {
            return false;
        }
        return true;
    };
    WaitQueueEvent faultData = {};
    auto it = std::find_if(waitQueue_.begin(), waitQueue_.end(), find_fun);
    if (it == waitQueue_.end()) {
        return faultData;
    }
    return *it;
}

bool AppRegister::CheckFindFdError(const int32_t findFd)
{
    if (findFd < 0) {
        MMI_LOGE(" IsMultimodeInputReady: Find fd error, errCode:%{public}d", FD_FIND_FAIL);
        return false;
    }
    return true;
}

bool AppRegister::CheckConnectionIsDead(const int32_t findFd)
{
    if (connectState_.find(findFd) == connectState_.end()) {
        MMI_LOGE("IsMultimodeInputReady: The connection is dead! fd:%{public}d, errCode:%{public}d",
                 findFd, CONN_BREAK);
        return false;
    }
    return true;
}

bool AppRegister::CheckWaitQueueBlock(ssize_t currentTime, ssize_t timeOut, const int32_t findFd)
{
    for (auto iter = waitQueue_.begin(); iter != waitQueue_.end(); ++iter) {
        if (findFd == iter->fd) {
            if (currentTime >= (iter->serverTime + timeOut)) {
                MMI_LOGE("IsMultimodeInputReady: The wait queue is blocked! fd:%{public}d,idMsg:%{public}d,"
                         "errCode:%{public}d", findFd, iter->event, WAITING_QUEUE_FULL);
                waitQueue_.erase(iter);
                return false;
            }
        }
    }
    return true;
}

void AppRegister::DeleteEventFromWaitQueue(int32_t fd, int32_t idMsg)
{
    std::lock_guard<std::mutex> lock(mu_);
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    for (auto iter = waitQueue_.begin(); iter != waitQueue_.end(); ++iter) {
        if ((iter->event == idMsg) && (iter->fd == fd)) {
            waitQueue_.erase(iter);
            break;
        }
    }
}

bool AppRegister::OnAnrLocked(int32_t fd) const
{
    MMI_LOGE("Dispatch Timeout, Application Not Responding. fd:%{public}d,errCode:%{public}d",
             fd, APP_NOT_RESP);
    return true;
}

void AppRegister::RegisterConnectState(int32_t fd)
{
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    std::lock_guard<std::mutex> lock(mu_);
    connectState_.insert(std::pair<int32_t, int8_t>(fd, 0));
}

void AppRegister::UnregisterConnectState(int32_t fd)
{
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    std::lock_guard<std::mutex> lock(mu_);

    auto iter = connectState_.find(fd);
    if (iter != connectState_.end()) {
        connectState_.erase(iter);
    }
}
} // namespace MMI
} // namespace OHOS
