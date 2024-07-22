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

#ifndef SOCKET_SESSION_MANAGER_H
#define SOCKET_SESSION_MANAGER_H

#include <functional>
#include <map>

#include "nocopyable.h"

#include "app_mgr_interface.h"
#include "application_state_observer_stub.h"

#include "epoll_manager.h"
#include "i_epoll_event_source.h"
#include "i_socket_session_manager.h"
#include "socket_session.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SocketSessionManager final : public ISocketSessionManager, public IEpollEventSource {
public:
    SocketSessionManager() = default;
    ~SocketSessionManager() = default;
    DISALLOW_COPY_AND_MOVE(SocketSessionManager);

    int32_t Init();

    void AddSessionDeletedCallback(int32_t pid, std::function<void(SocketSessionPtr)> callback) override;
    void RemoveSessionDeletedCallback(int32_t pid) override;
    int32_t AllocSocketFd(const std::string& programName, int32_t moduleType, int32_t tokenType,
                          int32_t uid, int32_t pid, int32_t& clientFd) override;
    SocketSessionPtr FindSessionByPid(int32_t pid) const override;

    int32_t GetFd() const override;
    void Dispatch(const struct epoll_event &ev) override;
    void RegisterApplicationState() override;

private:
    class AppStateObserver final : public AppExecFwk::ApplicationStateObserverStub {
    public:
        explicit AppStateObserver(SocketSessionManager &socketSessionManager)
            : socketSessionManager_(socketSessionManager) {}
        ~AppStateObserver() = default;
        void OnProcessDied(const AppExecFwk::ProcessData &processData) override;
    private:
        SocketSessionManager &socketSessionManager_;
    };

private:
    bool SetBufferSize(int32_t sockFd, int32_t bufSize);
    void DispatchOne();
    void ReleaseSession(int32_t fd);
    void ReleaseSessionByPid(int32_t pid);
    std::shared_ptr<SocketSession> FindSession(int32_t fd) const;
    sptr<AppExecFwk::IAppMgr> GetAppMgr();
    bool AddSession(std::shared_ptr<SocketSession> session);
    void DumpSession(const std::string& title) const;
    void NotifySessionDeleted(std::shared_ptr<SocketSession> sessionPtr);

    EpollManager epollMgr_;
    std::map<int32_t, std::shared_ptr<SocketSession>> sessions_;
    std::map<int32_t, std::function<void(SocketSessionPtr)>> callbacks_;
    sptr<AppStateObserver> appStateObserver_ { nullptr };
};

inline int32_t SocketSessionManager::GetFd() const
{
    return epollMgr_.GetFd();
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SOCKET_SESSION_MANAGER_H