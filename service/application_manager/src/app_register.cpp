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
#if 0
const int32_t INPUT_UI_TIMEOUT_TIME = 5 * 1000000;
const int32_t INPUT_NUI_TIMEOUT_TIME = 10 * 1000000;
const int32_t WAIT_QUEUE_EVENTS_MAX = 128;
#endif
AppRegister::AppRegister()
{
}

AppRegister::~AppRegister()
{
}

bool AppRegister::Init(UDSServer& udsServer)
{
    MMI_LOGD("enter");
    mapSurface_.clear();
    waitQueue_.clear();
    mapConnectState_.clear();
    if (mu_.try_lock()) {
        mu_.unlock();
    }
    udsServer_ = &udsServer;
    MMI_LOGD("leave");
    return true;
}

const AppInfo& AppRegister::FindByWinId(int32_t windowId)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    auto it = mapSurface_.find(windowId);
    if (it != mapSurface_.end()) {
        return it->second;
    }
    MMI_LOGD("leave");
    return AppRegister::appInfoError_;
}

const AppInfo& AppRegister::FindBySocketFd(int32_t fd)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    CHKR(fd >= 0, PARAM_INPUT_INVALID, appInfoError_);
    for (const auto &item : mapSurface_) {
        if (item.second.fd == fd) {
            return item.second;
        }
    }
    MMI_LOGD("leave");
    return AppRegister::appInfoError_;
}

void AppRegister::RegisterAppInfoforServer(const AppInfo& appInfo)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    mapSurface_.insert(std::pair<int32_t, AppInfo>(appInfo.windowId, appInfo));
    AddId(fds_, appInfo.fd);
    MMI_LOGD("leave");
}

void AppRegister::UnregisterAppInfoBySocketFd(int32_t fd)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    UnregisterBySocketFd(fd);
    MMI_LOGD("leave");
}

void AppRegister::UnregisterBySocketFd(int32_t fd)
{
    MMI_LOGD("enter");
    auto it = mapSurface_.begin();
    while (it != mapSurface_.end()) {
        if (it->second.fd == fd) {
            it = mapSurface_.erase(it);
        } else {
            it++;
        }
    }
    MMI_LOGD("leave");
}

std::map<int32_t, AppInfo>::iterator AppRegister::EraseAppInfo(const std::map<int32_t, AppInfo>::iterator &it)
{
    MMI_LOGD("enter");
    return mapSurface_.erase(it);
}

std::map<int32_t, AppInfo>::iterator AppRegister::UnregisterAppInfo(int32_t winId)
{
    MMI_LOGD("enter");
    if (winId <= 0) {
        return mapSurface_.end();
    }
    auto itr = mapSurface_.find(winId);
    if (itr == mapSurface_.end()) {
        return mapSurface_.end();
    }
    MMI_LOGD("leave");
    return EraseAppInfo(itr);
}

void AppRegister::PrintfMap()
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto &item : mapSurface_) {
        std::cout << "mapSurface " << item.second.abilityId << ", " << item.second.windowId <<
            ", " << item.second.fd << std::endl;
    }
    MMI_LOGD("leave");
}

void OHOS::MMI::AppRegister::Dump(int32_t fd)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    mprintf(fd, "AppInfos: count=%d", mapSurface_.size());
    for (const auto &item : mapSurface_) {
        mprintf(fd, "\tabilityId=%d windowId=%d fd=%d bundlerName=%s appName=%s", item.second.abilityId,
                item.second.windowId, item.second.fd, item.second.bundlerName.c_str(), item.second.appName.c_str());
    }
    MMI_LOGD("leave");
}

void AppRegister::SurfacesDestroyed(const std::vector<int32_t> &desList)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    for (const auto &item : desList) {
        UnregisterAppInfo(item);
    }
    MMI_LOGD("leave");
}

int32_t AppRegister::QueryMapSurfaceNum()
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    MMI_LOGD("leave");
    return static_cast<int32_t>(mapSurface_.size());
}

bool AppRegister::IsMultimodeInputReady(MmiMessageId idMsg, const int32_t findFd, uint64_t inputTime,
                                        uint64_t westonTime)
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
    MMI_LOGD("enter");
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
    MMI_LOGD("leave");
    return *it;
}

bool AppRegister::CheckFindFdError(const int32_t findFd)
{
    MMI_LOGD("enter");
    if (findFd < 0) {
        MMI_LOGE(" IsMultimodeInputReady: Find fd error, errCode:%{public}d", FD_FIND_FAIL);
        return false;
    }
    MMI_LOGD("leave");
    return true;
}

bool AppRegister::CheckConnectionIsDead(const int32_t findFd)
{
    MMI_LOGD("enter");
    if (mapConnectState_.find(findFd) == mapConnectState_.end()) {
        MMI_LOGE("IsMultimodeInputReady: The connection is dead! fd:%{public}d,errCode:%{public}d",
                 findFd, CONN_BREAK);
        return false;
    }
    MMI_LOGD("leave");
    return true;
}

bool AppRegister::CheckWaitQueueBlock(ssize_t currentTime, ssize_t timeOut, const int32_t findFd)
{
    MMI_LOGD("enter");
    for (auto iter = waitQueue_.begin(); iter != waitQueue_.end(); iter++) {
        if (findFd == iter->fd) {
            if (currentTime >= (iter->serverTime + timeOut)) {
                MMI_LOGE("IsMultimodeInputReady: The wait queue is blocked! fd:%{public}d,idMsg:%{public}d,"
                         "errCode:%{public}d", findFd, iter->event, WAITING_QUEUE_FULL);
                waitQueue_.erase(iter);
                return false;
            }
        }
    }
    MMI_LOGD("leave");
    return true;
}

void AppRegister::DeleteEventFromWaitQueue(int32_t fd, int32_t idMsg)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mu_);
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    for (auto iter = waitQueue_.begin(); iter != waitQueue_.end(); iter++) {
        if ((iter->event == idMsg) && (iter->fd == fd)) {
            waitQueue_.erase(iter);
            break;
        }
    }
    MMI_LOGD("leave");
}

bool AppRegister::OnAnrLocked(int32_t fd) const
{
    MMI_LOGD("enter");
    MMI_LOGE("Dispatch Timeout, Application Not Responding. fd:%{public}d,errCode:%{public}d",
             fd, APP_NOT_RESP);
    MMI_LOGD("leave");
    return true;
}

void AppRegister::RegisterConnectState(int32_t fd)
{
    MMI_LOGD("enter");
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    std::lock_guard<std::mutex> lock(mu_);
    mapConnectState_.insert(std::pair<int32_t, int8_t>(fd, 0));
    MMI_LOGD("leave");
}

void AppRegister::UnregisterConnectState(int32_t fd)
{
    MMI_LOGD("enter");
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    std::lock_guard<std::mutex> lock(mu_);

    auto iter = mapConnectState_.find(fd);
    if (iter != mapConnectState_.end()) {
        mapConnectState_.erase(iter);
    }
    MMI_LOGD("leave");
}
}
}
