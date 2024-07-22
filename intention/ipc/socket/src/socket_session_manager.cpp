/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "socket_session_manager.h"

#include <algorithm>

#include <sys/socket.h>
#include <unistd.h>

#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "SocketSessionManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t MAX_EPOLL_EVENTS { 64 };
} // namespace

int32_t SocketSessionManager::Init()
{
    return epollMgr_.Open();
}

void SocketSessionManager::RegisterApplicationState()
{
    CALL_DEBUG_ENTER;
    auto appMgr = GetAppMgr();
    CHKPV(appMgr);
    appStateObserver_ = sptr<AppStateObserver>::MakeSptr(*this);
    auto err = appMgr->RegisterApplicationStateObserver(appStateObserver_);
    if (err != RET_OK) {
        appStateObserver_ = nullptr;
        FI_HILOGE("IAppMgr::RegisterApplicationStateObserver fail, error:%{public}d", err);
    }
}

void SocketSessionManager::AppStateObserver::OnProcessDied(const AppExecFwk::ProcessData &processData)
{
    FI_HILOGI("\'%{public}s\' died, pid:%{public}d", processData.bundleName.c_str(), processData.pid);
    socketSessionManager_.ReleaseSessionByPid(processData.pid);
}

int32_t SocketSessionManager::AllocSocketFd(const std::string& programName, int32_t moduleType, int32_t tokenType,
                                            int32_t uid, int32_t pid, int32_t& clientFd)
{
    CALL_DEBUG_ENTER;
    int32_t sockFds[2] { -1, -1 };

    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds) != 0) {
        FI_HILOGE("Call socketpair failed, errno:%{public}s", ::strerror(errno));
        return RET_ERR;
    }
    static constexpr size_t BUFFER_SIZE { 32 * 1024 };
    static constexpr size_t NATIVE_BUFFER_SIZE { 64 * 1024 };
    std::shared_ptr<SocketSession> session { nullptr };

    if (!SetBufferSize(sockFds[0], BUFFER_SIZE)) {
        goto CLOSE_SOCK;
    }
    if (!SetBufferSize(sockFds[1], tokenType == TokenType::TOKEN_NATIVE ? NATIVE_BUFFER_SIZE : BUFFER_SIZE)) {
        goto CLOSE_SOCK;
    }

    session = std::make_shared<SocketSession>(programName, moduleType, tokenType, sockFds[0], uid, pid);
    if (epollMgr_.Add(*session) != RET_OK) {
        goto CLOSE_SOCK;
    }
    if (!AddSession(session)) {
        FI_HILOGE("AddSession failed, errCode:%{public}d", ADD_SESSION_FAIL);
        goto CLOSE_SOCK;
    }

    clientFd = sockFds[1];
    return RET_OK;

CLOSE_SOCK:
    if (::close(sockFds[0]) != 0) {
        FI_HILOGE("close(%{public}d) failed:%{public}s", sockFds[0], ::strerror(errno));
    }
    if (::close(sockFds[1]) != 0) {
        FI_HILOGE("close(%{public}d) failed:%{public}s", sockFds[1], ::strerror(errno));
    }
    return RET_ERR;
}

bool SocketSessionManager::SetBufferSize(int32_t sockFd, int32_t bufSize)
{
    if (::setsockopt(sockFd, SOL_SOCKET, SO_SNDBUF, &bufSize, sizeof(bufSize)) != 0) {
        FI_HILOGE("setsockopt(%{public}d) failed:%{public}s", sockFd, ::strerror(errno));
        return false;
    }
    if (::setsockopt(sockFd, SOL_SOCKET, SO_RCVBUF, &bufSize, sizeof(bufSize)) != 0) {
        FI_HILOGE("setsockopt(%{public}d) failed:%{public}s", sockFd, ::strerror(errno));
        return false;
    }
    return true;
}

SocketSessionPtr SocketSessionManager::FindSessionByPid(int32_t pid) const
{
    auto iter = std::find_if(sessions_.cbegin(), sessions_.cend(),
        [pid](const auto &item) {
            return ((item.second != nullptr) && (item.second->GetPid() == pid));
        });
    return (iter != sessions_.cend() ? iter->second : nullptr);
}

void SocketSessionManager::Dispatch(const struct epoll_event &ev)
{
    if ((ev.events & EPOLLIN) == EPOLLIN) {
        DispatchOne();
    } else if ((ev.events & (EPOLLHUP | EPOLLERR)) != 0) {
        FI_HILOGE("Epoll hangup:%{public}s", ::strerror(errno));
    }
}

void SocketSessionManager::DispatchOne()
{
    struct epoll_event evs[MAX_EPOLL_EVENTS];
    int32_t cnt = epollMgr_.WaitTimeout(evs, MAX_EPOLL_EVENTS, 0);

    for (int32_t index = 0; index < cnt; ++index) {
        IEpollEventSource *source = reinterpret_cast<IEpollEventSource *>(evs[index].data.ptr);
        CHKPC(source);
        if ((evs[index].events & EPOLLIN) == EPOLLIN) {
            source->Dispatch(evs[index]);
        } else if ((evs[index].events & (EPOLLHUP | EPOLLERR)) != 0) {
            FI_HILOGE("Epoll hangup:%{public}s", ::strerror(errno));
            ReleaseSession(source->GetFd());
        }
    }
}

void SocketSessionManager::ReleaseSession(int32_t fd)
{
    CALL_DEBUG_ENTER;
    if (auto iter = sessions_.find(fd); iter != sessions_.end()) {
        auto session = iter->second;
        sessions_.erase(iter);

        if (session != nullptr) {
            epollMgr_.Remove(*session);
            NotifySessionDeleted(session);
        }
    }
    DumpSession("DelSession");
}

void SocketSessionManager::ReleaseSessionByPid(int32_t pid)
{
    CALL_DEBUG_ENTER;
    auto iter = std::find_if(sessions_.cbegin(), sessions_.cend(),
        [pid](const auto &item) {
            return ((item.second != nullptr) && (item.second->GetPid() == pid));
        });
    if (iter != sessions_.end()) {
        auto session = iter->second;
        if (session != nullptr) {
            epollMgr_.Remove(*session);
            NotifySessionDeleted(session);
        }
        sessions_.erase(iter);
    }
    DumpSession("DelSession");
}

sptr<AppExecFwk::IAppMgr> SocketSessionManager::GetAppMgr()
{
    CALL_INFO_TRACE;
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHKPP(saMgr);
    auto appMgrObj = saMgr->GetSystemAbility(APP_MGR_SERVICE_ID);
    CHKPP(appMgrObj);
    return iface_cast<AppExecFwk::IAppMgr>(appMgrObj);
}

std::shared_ptr<SocketSession> SocketSessionManager::FindSession(int32_t fd) const
{
    auto iter = sessions_.find(fd);
    return (iter != sessions_.cend() ? iter->second : nullptr);
}

void SocketSessionManager::DumpSession(const std::string &title) const
{
    FI_HILOGD("in %s:%s", __func__, title.c_str());
    int32_t i = 0;

    for (auto &[_, session] : sessions_) {
        CHKPC(session);
        FI_HILOGD("%{public}d, %s", i, session->ToString().c_str());
        i++;
    }
}

bool SocketSessionManager::AddSession(std::shared_ptr<SocketSession> session)
{
    CALL_DEBUG_ENTER;
    CHKPF(session);
    if (sessions_.size() >= MAX_SESSION_ALARM) {
        FI_HILOGE("The number of connections exceeds limit(%{public}zu)", MAX_SESSION_ALARM);
        return false;
    }
    auto [_, inserted] = sessions_.emplace(session->GetFd(), session);
    if (!inserted) {
        FI_HILOGE("Session(%{public}d) has been recorded", session->GetFd());
        return false;
    }
    DumpSession("AddSession");
    return true;
}

void SocketSessionManager::AddSessionDeletedCallback(int32_t pid, std::function<void(SocketSessionPtr)> callback)
{
    if (callback == nullptr) {
        FI_HILOGE("Callback is none");
        return;
    }
    auto [_, inserted] = callbacks_.emplace(pid, callback);
    if (!inserted) {
        FI_HILOGW("Duplication of session-lost callback for (%{public}d)", pid);
    }
    FI_HILOGI("Start watching socket-session(%{public}d)", pid);
}

void SocketSessionManager::RemoveSessionDeletedCallback(int32_t pid)
{
    FI_HILOGI("Stop watching socket-session(%{public}d)", pid);
    callbacks_.erase(pid);
}

void SocketSessionManager::NotifySessionDeleted(std::shared_ptr<SocketSession> session)
{
    CALL_DEBUG_ENTER;
    FI_HILOGD("Session lost, pid:%{public}d", session->GetPid());
    if (auto iter = callbacks_.find(session->GetPid()); iter != callbacks_.end()) {
        if (iter->second) {
            iter->second(session);
        }
        callbacks_.erase(iter);
    }
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
