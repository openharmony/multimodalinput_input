/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef UDS_SERVER_H
#define UDS_SERVER_H

#include "uds_socket.h"

#include "i_uds_server.h"

namespace OHOS {
namespace MMI {
enum EpollEventType {
    EPOLL_EVENT_BEGIN = 0,
    EPOLL_EVENT_INPUT = EPOLL_EVENT_BEGIN,
    EPOLL_EVENT_SOCKET,
    EPOLL_EVENT_SIGNAL,
    EPOLL_EVENT_ETASK,
    EPOLL_EVENT_END,
};

struct mmi_epoll_event {
    int32_t fd{ 0 };
    EpollEventType event_type{ EPOLL_EVENT_BEGIN };
};

using MsgServerFunCallback = std::function<void(SessionPtr, NetPacket&)>;
class UDSServer : public UDSSocket, public IUdsServer {
public:
    UDSServer() = default;
    DISALLOW_COPY_AND_MOVE(UDSServer);
    virtual ~UDSServer();
    void UdsStop();
    bool SendMsg(int32_t fd, NetPacket& pkt);
    void Multicast(const std::vector<int32_t>& fdList, NetPacket& pkt);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    int32_t GetClientFd(int32_t pid) const;
    int32_t GetClientPid(int32_t fd) const;
    void AddSessionDeletedCallback(std::function<void(SessionPtr)> callback);
    int32_t AddSocketPairInfo(const std::string& programName, const int32_t moduleType, const int32_t uid,
        const int32_t pid, int32_t& serverFd, int32_t& toReturnClientFd,
        int32_t& tokenType, uint32_t tokenId, bool isRealProcessName) override;

    SessionPtr GetSession(int32_t fd) const;
    SessionPtr GetSessionByPid(int32_t pid) const override;

    void AddEpollEvent(int32_t fd, std::shared_ptr<mmi_epoll_event> epollEvent);
    void RemoveEpollEvent(int32_t fd);

protected:
    virtual void OnConnected(SessionPtr s);
    virtual void OnDisconnected(SessionPtr s);
    virtual int32_t AddEpoll(EpollEventType type, int32_t fd, bool readOnly = false);

    void SetRecvFun(MsgServerFunCallback fun);
    void ReleaseSession(int32_t fd, epoll_event& ev);
    void OnPacket(int32_t fd, NetPacket& pkt);
    void OnEpollRecv(int32_t fd, epoll_event& ev);
    void OnEpollEvent(epoll_event& ev);
    bool AddSession(SessionPtr ses);
    void DelSession(int32_t fd);
    void DumpSession(const std::string& title);
    void NotifySessionDeleted(SessionPtr ses);
    int32_t SetFdProperty(int32_t &tokenType, int32_t &serverFd, int32_t &toReturnClientFd,
        const std::string &programName, bool &readOnly);
    void EarseSessionByFd(int32_t fd);
    size_t GetSessionSize();
    bool InsertSession(int32_t fd, SessionPtr sp);
    std::map<int32_t, SessionPtr> GetSessionMapCopy();
    void ClearSessionMap();

protected:
    MsgServerFunCallback recvFun_ { nullptr };
    std::map<int32_t, SessionPtr> sessionsMap_;
    mutable std::mutex sessionsMapMutex_;
    std::map<int32_t, int32_t> idxPidMap_;
    mutable std::mutex idxPidMapMutex_;
    std::map<int32_t, CircleStreamBuffer> circleBufMap_;
    std::list<std::function<void(SessionPtr)>> callbacks_;
    std::map<int32_t, std::shared_ptr<mmi_epoll_event>> epollEventMap_;
    mutable int32_t pid_ { -1 };
};
} // namespace MMI
} // namespace OHOS
#endif // UDS_SERVER_H