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
#include "app_register.h"
#include "util_ex.h"
#include "mmi_server.h"

namespace OHOS {
namespace MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "AppRegister" };
    }
const int32_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
const int32_t INPUT_NUI_TIMEOUT_TIME = 10 * 1000000;
const int32_t WAIT_QUEUE_EVENTS_MAX = 128;

AppRegister::AppRegister()
{
}

AppRegister::~AppRegister()
{
}

bool AppRegister::Init(UDSServer& udsServer)
{
    teseArgv_ = 0;
#ifdef OHOS_AUTO_TEST_FRAME
    autoTestFrameFd_ = 0;
#endif  // OHOS_AUTO_TEST_FRAME
    mapSurface.clear();
    waitQueue_.clear();
    mapConnectState_.clear();
    if (mu_.try_lock()) {
        mu_.unlock();
    }
    udsServer_ = &udsServer;
    return true;
}

const AppInfo& AppRegister::FindByWinId(int32_t windowId)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = mapSurface.find(windowId);
    if (it != mapSurface.end()) {
        return it->second;
    }
    return AppRegister::AppInfoError_;
}

const AppInfo& AppRegister::FindBySocketFd(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    CHKR(fd >= 0, PARAM_INPUT_INVALID, AppInfoError_);
    return FindAppInfoBySocketFd(fd);
}

const AppInfo& AppRegister::FindAppInfoBySocketFd(int32_t fd)
{
    for (auto iter = mapSurface.begin(); iter != mapSurface.end(); iter++) {
        if (iter->second.fd == fd) {
            return iter->second;
        }
    }
    return AppRegister::AppInfoError_;
}

void AppRegister::RegisterAppInfoforServer(const AppInfo& appInfo)
{
    std::lock_guard<std::mutex> lock(mu_);
    mapSurface.insert(std::pair<int32_t, AppInfo>(appInfo.windowId, appInfo));
}

void AppRegister::UnregisterAppInfoforServer(int32_t abilityId)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = mapSurface.begin();
    while (it != mapSurface.end()) {
        if (it->second.abilityId == abilityId) {
            it = mapSurface.erase(it);
        } else {
            it++;
        }
    }
}

void AppRegister::UnregisterAppInfoforServer(const AppInfo& appInfo)
{
    std::lock_guard<std::mutex> lock(mu_);
    auto it = mapSurface.begin();
    while (it != mapSurface.end()) {
        if (it->second.abilityId == appInfo.abilityId) {
            it = mapSurface.erase(it);
        } else {
            it++;
        }
    }
}

void AppRegister::UnregisterAppInfoBySocketFd(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    UnregisterBySocketFd(fd);
}

void AppRegister::UnregisterBySocketFd(int32_t fd)
{
    auto it = mapSurface.begin();
    while (it != mapSurface.end()) {
        if (it->second.fd == fd) {
            it = mapSurface.erase(it);
        } else {
            it++;
        }
    }
}

void AppRegister::PrintfMap()
{
    std::lock_guard<std::mutex> lock(mu_);
    for (auto i : mapSurface) {
        std::cout << "mapSurface " << i.second.abilityId << ", " << i.second.windowId <<
            ", " << i.second.fd << std::endl;
    }
}

void OHOS::MMI::AppRegister::Dump(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mu_);
    mprintf(fd, "AppInfos: count=%d", mapSurface.size());
    for (auto& it : mapSurface) {
        mprintf(fd, "\tabilityId=%d windowId=%d fd=%d bundlerName=%s appName=%s", it.second.abilityId,
                it.second.windowId, it.second.fd, it.second.bundlerName.c_str(), it.second.appName.c_str());
    }
}

int32_t AppRegister::QueryMapSurfaceNum()
{
    std::lock_guard<std::mutex> lock(mu_);
    return static_cast<int32_t>(mapSurface.size());
}

bool AppRegister::IsMultimodeInputReady(ssize_t currentTime, MmiMessageId idMsg, const int32_t findFd,
                                        int32_t connectState, int32_t bufferState)
{
    std::lock_guard<std::mutex> lock(mu_);
    WaitQueueEvent newEvent = {findFd, currentTime, 0};

    ssize_t timeOut = INPUT_NUI_TIMEOUT_TIME;
    if ((idMsg == MmiMessageId::ON_KEY) || (idMsg == MmiMessageId::ON_TOUCH)) {
        timeOut = INPUT_UI_TIMEOUT_TIME;
    }

    if (!CheckFindFdError(findFd)) {
        return false;
    }
    if (!CheckConnectionIsDead(currentTime, timeOut, findFd, connectState)) {
        return false;
    }
    if (!CheckBufferIsFull(currentTime, timeOut, findFd, bufferState)) {
        return false;
    }
    if (!CheckWaitQueueBlock(currentTime, timeOut, findFd)) {
        return false;
    }

    if (waitQueue_.size() > WAIT_QUEUE_EVENTS_MAX) {
        waitQueue_.clear();
        MMI_LOGT("The Wait Queue is full! Clear it! \n");
    }
    waitQueue_.push_back(newEvent);
    return true;
}

bool AppRegister::CheckFindFdError(const int32_t findFd)
{
    if (-1 == findFd) {
        MMI_LOGE(" IsMultimodeInputReady: Find fd error! errCode:%{public}d \n", FD_FIND_FAIL);
        OnAnrLocked(findFd);
        return false;
    }
    return true;
}

bool AppRegister::CheckConnectionIsDead(ssize_t currentTime, ssize_t timeOut,
                                        const int32_t findFd, int32_t connectState)
{
    if (-1 == connectState) {
        MMI_LOGE(" IsMultimodeInputReady: The connection is dead! errCode:%{public}d \n", CONN_BREAK);
        auto appInfo = FindAppInfoBySocketFd(findFd);
        for (auto iter = waitQueue_.begin(); iter != waitQueue_.end(); iter++) {
            if (findFd != iter->fd) {
                continue;
            }
            if (currentTime >= (iter->currentTime + timeOut)) {
                waitQueue_.erase(iter);
                WinMgr->EraseSurfaceInfo(appInfo.windowId);
                UnregisterBySocketFd(findFd);
                OnAnrLocked(findFd);
                return false;
            }
            return false;
        }
        WinMgr->EraseSurfaceInfo(appInfo.windowId);
        UnregisterBySocketFd(findFd);
        OnAnrLocked(findFd);
        return false; // Discard the event!
    }
    return true;
}

bool AppRegister::CheckBufferIsFull(ssize_t currentTime, ssize_t timeOut,
                                    const int32_t findFd, int32_t bufferState)
{
    if (-1 == bufferState) {
        MMI_LOGE(" IsMultimodeInputReady: The buffer is full! errCode:%{public}d \n", SOCKET_BUF_FULL);
        auto appInfo = FindAppInfoBySocketFd(findFd);
        for (auto iter = waitQueue_.begin(); iter != waitQueue_.end(); iter++) {
            if (findFd != iter->fd) {
                continue;
            }
            if (currentTime >= (iter->currentTime + timeOut)) {
                waitQueue_.erase(iter);
                WinMgr->EraseSurfaceInfo(appInfo.windowId);
                UnregisterBySocketFd(findFd);
                OnAnrLocked(findFd);
                return false;
            }
            return false;
        }
        WinMgr->EraseSurfaceInfo(appInfo.windowId);
        UnregisterBySocketFd(findFd);
        OnAnrLocked(findFd);
        return false; // Discard the event!
    }
    return true;
}

bool AppRegister::CheckWaitQueueBlock(ssize_t currentTime, ssize_t timeOut, const int32_t findFd)
{
    for (auto iter = waitQueue_.begin(); iter != waitQueue_.end(); iter++) {
        if (findFd == iter->fd) {
            if (currentTime >= (iter->currentTime + timeOut)) {
                MMI_LOGE("IsMultimodeInputReady: The wait queue is blocked! errCode:%{public}d \n",
                         WAITING_QUEUE_FULL);
                waitQueue_.erase(iter);
                OnAnrLocked(findFd);
                return false;
            }
            return true;
        }
    }
    return true;
}

void AppRegister::DeleteEventFromWaitQueue(ssize_t time, const int32_t fd)
{
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    for (auto iter = waitQueue_.begin(); iter != waitQueue_.end(); iter++) {
        if ((iter->currentTime == time) && (iter->fd == fd)) {
            waitQueue_.erase(iter);
            break;
        }
    }
}

bool AppRegister::OnAnrLocked(int32_t fd) const
{
    MMI_LOGE("Dispatch Timeout! The Application Not Responding !!! The fd is %{public}d. errCode:%{public}d \n",
             fd, APP_NOT_RESP);
    return true;
}

void AppRegister::RegisterConnectState(int32_t fd)
{
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    ConnectStateByFd newConnectStateByFd = {0, 0};
    mapConnectState_.insert(std::pair<int32_t, ConnectStateByFd>(fd, newConnectStateByFd));
}

void AppRegister::UnregisterConnectState(int32_t fd)
{
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    // Unregister all by fd
    UnregisterBySocketFd(fd);
    RegEventHM->UnregisterEventHandleBySocketFd(fd);

#ifdef OHOS_AUTO_TEST_FRAME
    if (autoTestFrameFd_ == fd) {
        AutoTestSetAutoTestFd(0);
    }
#endif  // OHOS_AUTO_TEST_FRAME

    auto iter = mapConnectState_.find(fd);
    if (iter != mapConnectState_.end()) {
        mapConnectState_.erase(iter);
    }
}

void AppRegister::ConnectStateInputBlocked(const int32_t fd)
{
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    auto iter = mapConnectState_.find(fd);
    if (iter != mapConnectState_.end()) {
        iter->second.inputBlocked = RET_ERR;
    }
}

// Auto-test frame code
#ifdef OHOS_AUTO_TEST_FRAME
void AppRegister::AutoTestSetAutoTestFd(int32_t fd)
{
    autoTestFrameFd_ = fd;
}

int32_t AppRegister::AutoTestGetAutoTestFd()
{
    return autoTestFrameFd_;
}

void AppRegister::AutoTestGetAllAppInfo(std::vector<AutoTestClientListPkt>& clientListPkt)
{
    AutoTestClientListPkt tempInfo;
    for (auto i : mapSurface) {
        tempInfo = {i.second.fd, i.second.windowId, i.second.abilityId};
        clientListPkt.push_back(tempInfo);
    }
}
#endif  // OHOS_AUTO_TEST_FRAME
}
}