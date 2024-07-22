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

#include "uds_server.h"

#include <cinttypes>
#include <list>

#include <sys/socket.h>

#include "dfx_hisysevent.h"
#include "i_multimodal_input_connect.h"
#include "mmi_log.h"
#include "multimodalinput_ipc_interface_code.h"
#include "util.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "UDSServer"

namespace OHOS {
namespace MMI {
UDSServer::~UDSServer()
{
    CALL_DEBUG_ENTER;
    UdsStop();
}

void UDSServer::UdsStop()
{
    if (epollFd_ != -1) {
        close(epollFd_);
        epollFd_ = -1;
    }

    for (const auto &item : sessionsMap_) {
        item.second->Close();
    }
    sessionsMap_.clear();
}

int32_t UDSServer::GetClientFd(int32_t pid) const
{
    auto it = idxPidMap_.find(pid);
    if (it == idxPidMap_.end()) {
        if (pid_ != pid) {
            pid_ = pid;
            MMI_HILOGE("Not found pid:%{public}d", pid);
        }
        return INVALID_FD;
    }
    return it->second;
}

int32_t UDSServer::GetClientPid(int32_t fd) const
{
    auto it = sessionsMap_.find(fd);
    if (it == sessionsMap_.end()) {
        MMI_HILOGE("Not found fd:%{public}d", fd);
        return INVALID_PID;
    }
    return it->second->GetPid();
}

bool UDSServer::SendMsg(int32_t fd, NetPacket& pkt)
{
    if (fd < 0) {
        MMI_HILOGE("The fd is less than 0");
        return false;
    }
    auto ses = GetSession(fd);
    if (ses == nullptr) {
        MMI_HILOGE("The fd:%{public}d not found, The message was discarded. errCode:%{public}d",
                   fd, SESSION_NOT_FOUND);
        return false;
    }
    return ses->SendMsg(pkt);
}

void UDSServer::Multicast(const std::vector<int32_t>& fdList, NetPacket& pkt)
{
    for (const auto &item : fdList) {
        SendMsg(item, pkt);
    }
}

int32_t UDSServer::AddSocketPairInfo(const std::string& programName,
    const int32_t moduleType, const int32_t uid, const int32_t pid,
    int32_t& serverFd, int32_t& toReturnClientFd, int32_t& tokenType)
{
    CALL_DEBUG_ENTER;
    int32_t sockFds[2] = { -1 };

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds) != 0) {
        MMI_HILOGE("Call socketpair failed, errno:%{public}d", errno);
        return RET_ERR;
    }
    serverFd = sockFds[0];
    toReturnClientFd = sockFds[1];
    if (serverFd < 0 || toReturnClientFd < 0) {
        MMI_HILOGE("Call fcntl failed, errno:%{public}d", errno);
        return RET_ERR;
    }

    SessionPtr sess = nullptr;
    if (SetFdProperty(tokenType, serverFd, toReturnClientFd) != RET_OK) {
        MMI_HILOGE("SetFdProperty failed");
        goto CLOSE_SOCK;
    }

    if (AddEpoll(EPOLL_EVENT_SOCKET, serverFd) != RET_OK) {
        MMI_HILOGE("epoll_ctl EPOLL_CTL_ADD failed, errCode:%{public}d", EPOLL_MODIFY_FAIL);
        goto CLOSE_SOCK;
    }
    sess = std::make_shared<UDSSession>(programName, moduleType, serverFd, uid, pid);
    if (sess == nullptr) {
        MMI_HILOGE("make_shared fail. programName:%{public}s, pid:%{public}d, errCode:%{public}d",
            programName.c_str(), pid, MAKE_SHARED_FAIL);
        goto CLOSE_SOCK;
    }
    sess->SetTokenType(tokenType);
    if (!AddSession(sess)) {
        MMI_HILOGE("AddSession fail errCode:%{public}d", ADD_SESSION_FAIL);
        goto CLOSE_SOCK;
    }
    OnConnected(sess);
    return RET_OK;

    CLOSE_SOCK:
    close(serverFd);
    serverFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
    close(toReturnClientFd);
    toReturnClientFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
    return RET_ERR;
}

int32_t UDSServer::SetFdProperty(int32_t& tokenType, int32_t& serverFd, int32_t& toReturnClientFd)
{
    static size_t bufferSize = 64 * 1024;
    static size_t serverBufferSize = 64 * 1024;
    static size_t nativeBufferSize = 128 * 1024;
#ifdef OHOS_BUILD_ENABLE_ANCO
    bufferSize = 512 * 1024;
    nativeBufferSize = 1024 * 1024;
#endif // OHOS_BUILD_ENABLE_ANCO

    if (setsockopt(serverFd, SOL_SOCKET, SO_SNDBUF, &serverBufferSize, sizeof(bufferSize)) != 0) {
        MMI_HILOGE("setsockopt serverFd failed, errno:%{public}d", errno);
        return RET_ERR;
    }
    if (setsockopt(serverFd, SOL_SOCKET, SO_RCVBUF, &serverBufferSize, sizeof(bufferSize)) != 0) {
        MMI_HILOGE("setsockopt serverFd failed, errno:%{public}d", errno);
        return RET_ERR;
    }
    if (tokenType == TokenType::TOKEN_NATIVE) {
        if (setsockopt(toReturnClientFd, SOL_SOCKET, SO_SNDBUF, &nativeBufferSize, sizeof(nativeBufferSize)) != 0) {
            MMI_HILOGE("setsockopt toReturnClientFd failed, errno:%{public}d", errno);
            return RET_ERR;
        }
        if (setsockopt(toReturnClientFd, SOL_SOCKET, SO_RCVBUF, &nativeBufferSize, sizeof(nativeBufferSize)) != 0) {
            MMI_HILOGE("setsockopt toReturnClientFd failed, errno:%{public}d", errno);
            return RET_ERR;
        }
    } else {
        if (setsockopt(toReturnClientFd, SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize)) != 0) {
            MMI_HILOGE("setsockopt toReturnClientFd failed, errno:%{public}d", errno);
            return RET_ERR;
        }
        if (setsockopt(toReturnClientFd, SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize)) != 0) {
            MMI_HILOGE("setsockopt toReturnClientFd failed, errno:%{public}d", errno);
            return RET_ERR;
        }
    }
    return RET_OK;
}

void UDSServer::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Uds_server information:\t");
    mprintf(fd, "uds_server: count=%zu", sessionsMap_.size());
    for (const auto &item : sessionsMap_) {
        std::shared_ptr<UDSSession> udsSession = item.second;
        CHKPV(udsSession);
        mprintf(fd,
                "Uid:%d | Pid:%d | Fd:%d | TokenType:%d | Descript:%s\t",
                udsSession->GetUid(), udsSession->GetPid(), udsSession->GetFd(),
                udsSession->GetTokenType(), udsSession->GetDescript().c_str());
    }
}

void UDSServer::OnConnected(SessionPtr sess)
{
    CHKPV(sess);
    MMI_HILOGI("Session desc:%{public}s", sess->GetDescript().c_str());
}

void UDSServer::OnDisconnected(SessionPtr sess)
{
    CHKPV(sess);
    MMI_HILOGI("Session desc:%{public}s", sess->GetDescript().c_str());
}

int32_t UDSServer::AddEpoll(EpollEventType type, int32_t fd)
{
    MMI_HILOGE("This information should not exist. Subclasses should implement this function");
    return RET_ERR;
}

void UDSServer::SetRecvFun(MsgServerFunCallback fun)
{
    recvFun_ = fun;
}

void UDSServer::ReleaseSession(int32_t fd, epoll_event& ev)
{
    CALL_DEBUG_ENTER;
    auto secPtr = GetSession(fd);
    if (secPtr != nullptr) {
        OnDisconnected(secPtr);
        DelSession(fd);
    } else {
        MMI_HILOGE("Get session secPtr is nullptr, fd:%{public}d", fd);
        DfxHisysevent::OnClientDisconnect(secPtr, fd, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
    }
    if (ev.data.ptr) {
        RemoveEpollEvent(fd);
        ev.data.ptr = nullptr;
    }
    if (auto it = circleBufMap_.find(fd); it != circleBufMap_.end()) {
        circleBufMap_.erase(it);
    } else {
        MMI_HILOGE("Can't find fd");
    }
    if (close(fd) == RET_OK) {
        DfxHisysevent::OnClientDisconnect(secPtr, fd, OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR);
    } else {
        DfxHisysevent::OnClientDisconnect(secPtr, fd, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT);
    }
}

void UDSServer::OnPacket(int32_t fd, NetPacket& pkt)
{
    auto sess = GetSession(fd);
    CHKPV(sess);
    recvFun_(sess, pkt);
}

void UDSServer::OnEpollRecv(int32_t fd, epoll_event& ev)
{
    if (fd < 0) {
        MMI_HILOGE("Invalid input param fd:%{public}d", fd);
        return;
    }
    auto& buf = circleBufMap_[fd];
    char szBuf[MAX_PACKET_BUF_SIZE] = {};
    for (int32_t i = 0; i < MAX_RECV_LIMIT; i++) {
        auto size = recv(fd, szBuf, MAX_PACKET_BUF_SIZE, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (size > 0) {
            if (!buf.Write(szBuf, size)) {
                MMI_HILOGW("Write data failed. size:%{public}zu", size);
            }
            OnReadPackets(buf, [this, fd] (NetPacket& pkt) { return this->OnPacket(fd, pkt); });
        } else if (size < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                MMI_HILOGD("Continue for errno EAGAIN|EINTR|EWOULDBLOCK size:%{public}zu, errno:%{public}d",
                    size, errno);
                continue;
            }
            MMI_HILOGE("Recv return %{public}zu errno:%{public}d", size, errno);
            break;
        } else {
            MMI_HILOGE("The client side disconnect with the server. size:0 errno:%{public}d", errno);
            ReleaseSession(fd, ev);
            break;
        }
        if (size < MAX_PACKET_BUF_SIZE) {
            break;
        }
    }
}

void UDSServer::OnEpollEvent(epoll_event& ev)
{
    CHKPV(ev.data.ptr);
    auto fd = ev.data.fd;
    if (fd < 0) {
        MMI_HILOGE("The fd less than 0, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_HILOGI("EPOLLERR or EPOLLHUP fd:%{public}d, ev.events:0x%{public}x", fd, ev.events);
        ReleaseSession(fd, ev);
    } else if (ev.events & EPOLLIN) {
        OnEpollRecv(fd, ev);
    }
}

void UDSServer::AddEpollEvent(int32_t fd, std::shared_ptr<mmi_epoll_event> epollEvent)
{
    MMI_HILOGI("Add %{public}d in epollEvent map", fd);
    epollEventMap_[fd] = epollEvent;
}

void UDSServer::RemoveEpollEvent(int32_t fd)
{
    MMI_HILOGI("Remove %{public}d in epollEvent map", fd);
    epollEventMap_.erase(fd);
}

void UDSServer::DumpSession(const std::string &title)
{
    MMI_HILOGD("in %s: %s", __func__, title.c_str());
    int32_t i = 0;
    for (auto &[key, value] : sessionsMap_) {
        CHKPV(value);
        MMI_HILOGD("%d, %s", i, value->GetDescript().c_str());
        i++;
    }
}

SessionPtr UDSServer::GetSession(int32_t fd) const
{
    auto it = sessionsMap_.find(fd);
    if (it == sessionsMap_.end()) {
        MMI_HILOGE("Session not found. fd:%{public}d", fd);
        return nullptr;
    }
    CHKPP(it->second);
    return it->second->GetSharedPtr();
}

SessionPtr UDSServer::GetSessionByPid(int32_t pid) const
{
    int32_t fd = GetClientFd(pid);
    if (fd <= 0) {
        if (pid_ != pid) {
            pid_ = pid;
            MMI_HILOGE("Session not found. pid:%{public}d", pid);
        }
        return nullptr;
    }
    return GetSession(fd);
}

bool UDSServer::AddSession(SessionPtr ses)
{
    CHKPF(ses);
    MMI_HILOGI("pid:%{public}d, fd:%{public}d", ses->GetPid(), ses->GetFd());
    auto fd = ses->GetFd();
    if (fd < 0) {
        MMI_HILOGE("The fd is less than 0");
        return false;
    }
    auto pid = ses->GetPid();
    if (pid <= 0) {
        MMI_HILOGE("Get process failed");
        return false;
    }
    idxPidMap_[pid] = fd;
    sessionsMap_[fd] = ses;
    DumpSession("AddSession");
    if (sessionsMap_.size() > MAX_SESSON_ALARM) {
        MMI_HILOGW("Too many clients. Warning Value:%{public}d, Current Value:%{public}zd",
                   MAX_SESSON_ALARM, sessionsMap_.size());
    }
    MMI_HILOGI("AddSession end");
    return true;
}

void UDSServer::DelSession(int32_t fd)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("fd:%{public}d", fd);
    if (fd < 0) {
        MMI_HILOGE("The fd less than 0, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
    auto pid = GetClientPid(fd);
    MMI_HILOGI("pid:%{public}d", pid);
    if (pid > 0) {
        idxPidMap_.erase(pid);
    }
    auto it = sessionsMap_.find(fd);
    if (it != sessionsMap_.end()) {
        NotifySessionDeleted(it->second);
        sessionsMap_.erase(it);
    }
    DumpSession("DelSession");
}

void UDSServer::AddSessionDeletedCallback(std::function<void(SessionPtr)> callback)
{
    CALL_DEBUG_ENTER;
    callbacks_.push_back(callback);
}

void UDSServer::NotifySessionDeleted(SessionPtr ses)
{
    CALL_DEBUG_ENTER;
    for (const auto &callback : callbacks_) {
        callback(ses);
    }
}
} // namespace MMI
} // namespace OHOS
