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

#include "uds_server.h"
#include <list>
#include <cinttypes>
#include <sys/socket.h>
#include "accesstoken_kit.h"
#include "i_multimodal_input_connect.h"
#include "ipc_skeleton.h"
#include "mmi_log.h"
#include "safe_keeper.h"
#include "uds_command_queue.h"
#include "util.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "UDSServer"};
    }
} // namespace MMI
} // namespace OHOS

OHOS::MMI::UDSServer::UDSServer() {}

OHOS::MMI::UDSServer::~UDSServer()
{
    MMI_LOGD("enter");
    UdsStop();
    MMI_LOGD("leave");
}

void OHOS::MMI::UDSServer::UdsStop()
{
    std::lock_guard<std::mutex> lock(mux_);
    isRunning_ = false;
    if (epollFd_ != -1) {
        close(epollFd_);
        epollFd_ = -1;
    }

    for (const auto &item : sessionsMap_) {
        item.second->Close();
    }
    sessionsMap_.clear();
}

int32_t OHOS::MMI::UDSServer::GetClientFd(int32_t pid)
{
    std::lock_guard<std::mutex> lock(mux_);
    auto it = idxPidMap_.find(pid);
    if (it == idxPidMap_.end()) {
        MMI_LOGE("find fd error, Invalid input parameter pid:%{public}d,errCode:%{public}d",
            pid, SESSION_NOT_FOUND);
        return RET_ERR;
    }
    return it->second;
}

int32_t OHOS::MMI::UDSServer::GetClientPid(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mux_);
    auto it = sessionsMap_.find(fd);
    if (it == sessionsMap_.end()) {
        MMI_LOGE("find pid error, Invalid input parameter fd:%{public}d,errCode:%{public}d",
            fd, SESSION_NOT_FOUND);
        return RET_ERR;
    }
    return it->second->GetPid();
}

bool OHOS::MMI::UDSServer::SendMsg(int32_t fd, NetPacket& pkt)
{
    std::lock_guard<std::mutex> lock(mux_);
    CHKF(fd >= 0, PARAM_INPUT_INVALID);
    auto ses = GetSession(fd);
    if (ses == nullptr) {
        MMI_LOGE("SendMsg fd:%{public}d not found, The message was discarded. errCode:%{public}d",
                 fd, SESSION_NOT_FOUND);
        return false;
    }
    return ses->SendMsg(pkt);
}

void OHOS::MMI::UDSServer::Broadcast(NetPacket& pkt)
{
    std::lock_guard<std::mutex> lock(mux_);
    for (const auto &item : sessionsMap_) {
        item.second->SendMsg(pkt);
    }
}

void OHOS::MMI::UDSServer::Multicast(const std::vector<int32_t>& fdList, NetPacket& pkt)
{
    for (const auto &item : fdList) {
        SendMsg(item, pkt);
    }
}

bool  OHOS::MMI::UDSServer::ClearDeadSessionInMap(const int32_t serverFd, const int32_t clientFd)
{
    auto it = sessionsMap_.find(serverFd);
    if (it != sessionsMap_.end()) {
        MMI_LOGE("The session(fd1:%{public}d) on the server side will be closed because it had in map"
            "errCode:%{public}d", serverFd, SESSION_NOT_FOUND);
        DelSession(serverFd);
    }

    it = sessionsMap_.find(clientFd);
    if (it != sessionsMap_.end()) {
        MMI_LOGE("The session(fd2:%{public}d) on the server side will be closed because it had in map"
            "errCode:%{public}d", clientFd, SESSION_NOT_FOUND);
        DelSession(clientFd);
    }
    return true;
}

int32_t OHOS::MMI::UDSServer::AddSocketPairInfo(const std::string& programName,
    const int32_t moduleType, const int32_t uid, const int32_t pid,
    int32_t& serverFd, int32_t& toReturnClientFd)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> lock(mux_);
    int32_t sockFds[2] = {};

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds) != 0) {
        MMI_LOGE("call socketpair fail, errno:%{public}d", errno);
        return RET_ERR;
    }

    serverFd = sockFds[0];
    toReturnClientFd = sockFds[1];
    if (toReturnClientFd < 0) {
        MMI_LOGE("call fcntl fail, errno:%{public}d", errno);
        return RET_ERR;
    }

    constexpr size_t bufferSize = 32 * 1024;
    setsockopt(sockFds[0], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sockFds[0], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sockFds[1], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sockFds[1], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    SetNonBlockMode(serverFd);

    MMI_LOGD("alloc socketpair, serverFd:%{public}d,clientFd:%{public}d(%{public}d)",
             serverFd, toReturnClientFd, sockFds[1]);
    auto closeSocketFdWhenError = [&serverFd, &toReturnClientFd] {
        close(serverFd);
        close(toReturnClientFd);
        serverFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
        toReturnClientFd = IMultimodalInputConnect::INVALID_SOCKET_FD;
    };

    std::list<std::function<void()> > cleanTaskList;
    auto cleanTaskWhenError = [cleanTaskList] {
        for (const auto &item : cleanTaskList) {
            item();
        }
    };

    cleanTaskList.push_back(closeSocketFdWhenError);

    if (!ClearDeadSessionInMap(serverFd, toReturnClientFd)) {
        cleanTaskWhenError();
        MMI_LOGE("IsSocketFdNotUsed error, errCode:%{public}d", CLEAR_DEAD_SESSION_FAIL);
        return RET_ERR;
    }

    int32_t ret = RET_OK;
    ret = AddEpoll(EPOLL_EVENT_SOCKET, serverFd);
    if (ret != RET_OK) {
        cleanTaskWhenError();
        MMI_LOGE("epoll_ctl EPOLL_CTL_ADD return %{public}d,errCode:%{public}d", ret, EPOLL_MODIFY_FAIL);
        return ret;
    }

    SessionPtr sess = std::make_shared<UDSSession>(programName, moduleType, serverFd, uid, pid);
    if (sess == nullptr) {
        cleanTaskWhenError();
        MMI_LOGE("make_shared fail. progName:%{public}s,pid:%{public}d,errCode:%{public}d",
            programName.c_str(), pid, MAKE_SHARED_FAIL);
        return RET_ERR;
    }
    AddPermission(sess);
#ifdef OHOS_BUILD_MMI_DEBUG
    sess->SetClientFd(toReturnClientFd);
#endif // OHOS__BUILD_MMI_DEBUG

    if (!AddSession(sess)) {
        cleanTaskWhenError();
        MMI_LOGE("AddSession fail errCode:%{public}d", ADD_SESSION_FAIL);
        return RET_ERR;
    }
    OnConnected(sess);
    return RET_OK;
}

void OHOS::MMI::UDSServer::AddPermission(SessionPtr sess)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t result;
    std::string permissionMonitor = "ohos.permission.INPUT_MONITORING";
    
    if (Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken) ==
        Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        MMI_LOGD("get type flag is TOKEN_HAP");
        result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionMonitor);
        MMI_LOGD("verify access result:%{public}d", result);
        if (result != Security::AccessToken::PERMISSION_GRANTED) {
            MMI_LOGD("permission is not granted");
            sess->AddPermission(false);
        }
    }
}

void OHOS::MMI::UDSServer::Dump(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mux_);
    mprintf(fd, "Sessions: count=%d", sessionsMap_.size());
    std::string strTmp = "fds:[";
    if (sessionsMap_.empty()) {
        strTmp = "fds:[]";
        mprintf(fd, "\t%s", strTmp.c_str());
        return;
    }
    for (const auto& item : sessionsMap_) {
        strTmp += std::to_string(item.second->GetFd()) + ",";
    }
    strTmp.resize(strTmp.size() - 1);
    strTmp += "]";
    mprintf(fd, "\t%s", strTmp.c_str());
}

void OHOS::MMI::UDSServer::OnConnected(SessionPtr s)
{
    MMI_LOGI("UDSServer::OnConnected session desc:%{public}s", s->GetDescript().c_str());
}

void OHOS::MMI::UDSServer::OnDisconnected(SessionPtr s)
{
    MMI_LOGI("UDSServer::OnDisconnected session desc:%{public}s", s->GetDescript().c_str());
}

int32_t OHOS::MMI::UDSServer::AddEpoll(EpollEventType type, int32_t fd)
{
    MMI_LOGE("UDSServer::AddEpoll This information should not exist. Subclasses should implement this function.");
    return RET_ERR;
}

void OHOS::MMI::UDSServer::SetRecvFun(MsgServerFunCallback fun)
{
    recvFun_ = fun;
}

void OHOS::MMI::UDSServer::ReleaseSession(int32_t fd, epoll_event& ev)
{
    auto secPtr = GetSession(fd);
    if (secPtr != nullptr) {
        OnDisconnected(secPtr);
        DelSession(fd);
    }
    if (ev.data.ptr) {
        free(ev.data.ptr);
        ev.data.ptr = nullptr;
    }
    if (auto it = circleBufMap_.find(fd); it != circleBufMap_.end()) {
        circleBufMap_.erase(it);
    }
    close(fd);
}

void OHOS::MMI::UDSServer::OnPacket(int32_t fd, NetPacket& pkt)
{
    auto sess = GetSession(fd);
    CHKPV(sess);
    recvFun_(sess, pkt);
}

void OHOS::MMI::UDSServer::OnEpollRecv(int32_t fd, epoll_event& ev)
{
    if (fd < 0) {
        MMI_LOGE("Invalid input param fd:%{public}d", fd);
        return;
    }
    auto& buf = circleBufMap_[fd];
    char szBuf[MAX_PACKET_BUF_SIZE] = {};
    for (int32_t i = 0; i < MAX_RECV_LIMIT; i++) {
        auto size = recv(fd, szBuf, MAX_PACKET_BUF_SIZE, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (size > 0) {
#ifdef OHOS_BUILD_HAVE_DUMP_DATA
            DumpData(szBuf, size, LINEINFO, "in %s, read message from fd: %d.", __func__, fd);
#endif
            if (!buf.Write(szBuf, size)) {
                MMI_LOGW("Write data faild. size:%{public}zu", size);
            }
            OnReadPackets(buf, std::bind(&UDSServer::OnPacket, this, fd, std::placeholders::_1));
        } else if (size < 0) {
            if (errno == EAGAIN || errno == EINTR || errno == EWOULDBLOCK) {
                MMI_LOGD("continue for errno EAGAIN|EINTR|EWOULDBLOCK size:%{public}zu errno:%{public}d",
                    size, errno);
                continue;
            }
            MMI_LOGE("recv return %{public}zu errno:%{public}d", size, errno);
            break;
        } else {
            MMI_LOGE("The client side disconnect with the server. size:0 errno:%{public}d", errno);
            ReleaseSession(fd, ev);
            break;
        }
        if (size < MAX_PACKET_BUF_SIZE) {
            break;
        }
    }
}

void OHOS::MMI::UDSServer::OnEpollEvent(epoll_event& ev)
{
    CHKPV(ev.data.ptr);
    auto fd = *static_cast<int32_t*>(ev.data.ptr);
    if (fd < 0) {
        MMI_LOGE("The fd less than 0, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_LOGD("EPOLLERR or EPOLLHUP fd:%{public}d,ev.events:0x%{public}x", fd, ev.events);
        ReleaseSession(fd, ev);
    } else if (ev.events & EPOLLIN) {
        OnEpollRecv(fd, ev);
    }
}

void OHOS::MMI::UDSServer::DumpSession(const std::string &title)
{
    MMI_LOGD("in %s: %s", __func__, title.c_str());
    int32_t i = 0;
    for (auto& r : sessionsMap_) {
        MMI_LOGD("%d, %s", i, r.second->GetDescript().c_str());
        i++;
    }
}

OHOS::MMI::SessionPtr OHOS::MMI::UDSServer::GetSession(int32_t fd) const
{
    auto it = sessionsMap_.find(fd);
    if (it == sessionsMap_.end()) {
        return nullptr;
    }
    if (it->second == nullptr) {
        return nullptr;
    }
    return it->second->GetPtr();
}

bool OHOS::MMI::UDSServer::AddSession(SessionPtr ses)
{
    CHKPF(ses);
    MMI_LOGD("AddSession pid:%{public}d,fd:%{public}d", ses->GetPid(), ses->GetFd());
    auto fd = ses->GetFd();
    CHKF(fd >= 0, VAL_NOT_EXP);
    auto pid = ses->GetPid();
    CHKF(pid > 0, VAL_NOT_EXP);
    idxPidMap_[pid] = fd;
    sessionsMap_[fd] = ses;
    DumpSession("AddSession");
    if (sessionsMap_.size() > MAX_SESSON_ALARM) {
        MMI_LOGW("Too many clients. Warning Value:%{public}d,Current Value:%{public}zd",
                 MAX_SESSON_ALARM, sessionsMap_.size());
    }
    MMI_LOGI("AddSession end");
    return true;
}

void OHOS::MMI::UDSServer::DelSession(int32_t fd)
{
    MMI_LOGD("DelSession begin fd:%{public}d", fd);
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    auto pid = GetClientPid(fd);
    if (pid > 0) {
        idxPidMap_.erase(pid);
    }
    auto it = sessionsMap_.find(fd);
    if (it != sessionsMap_.end()) {
        NotifySessionDeleted(it->second);
        sessionsMap_.erase(it);
    }
    DumpSession("DelSession");
    MMI_LOGI("DelSession end");
}

void OHOS::MMI::UDSServer::AddSessionDeletedCallback(std::function<void(SessionPtr)> callback)
{
    MMI_LOGD("Enter");
    callbacks_.push_back(callback);
    MMI_LOGD("Leave");
}

void OHOS::MMI::UDSServer::NotifySessionDeleted(SessionPtr ses)
{
    MMI_LOGD("Enter");
    for (const auto& callback : callbacks_) {
        callback(ses);
    }
    MMI_LOGD("Leave");
}

