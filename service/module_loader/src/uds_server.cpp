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

#include <cinttypes>
#include <list>

#include <sys/socket.h>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"

#include "i_multimodal_input_connect.h"
#include "mmi_log.h"
#include "util.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "UDSServer"};
} // namespace

UDSServer::UDSServer() {}

UDSServer::~UDSServer()
{
    CALL_LOG_ENTER;
    UdsStop();
}

void UDSServer::UdsStop()
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
    if (t_.joinable()) {
        t_.join();
    }
}

int32_t UDSServer::GetClientFd(int32_t pid)
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

int32_t UDSServer::GetClientPid(int32_t fd)
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

bool UDSServer::SendMsg(int32_t fd, NetPacket& pkt)
{
    std::lock_guard<std::mutex> lock(mux_);
    if (fd < 0) {
        MMI_LOGE("fd is less than 0");
        return false;
    }
    auto ses = GetSession(fd);
    if (ses == nullptr) {
        MMI_LOGE("fd:%{public}d not found, The message was discarded. errCode:%{public}d",
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
    int32_t& serverFd, int32_t& toReturnClientFd)
{
    CALL_LOG_ENTER;
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

void UDSServer::AddPermission(SessionPtr sess)
{
    uint32_t callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t result;
    std::string permissionMonitor = "ohos.permission.INPUT_MONITORING";
    
    if (Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken) ==
        Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        MMI_LOGD("get token type flag is TOKEN_HAP");
        result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionMonitor);
        MMI_LOGD("verify access token result:%{public}d", result);
        if (result != Security::AccessToken::PERMISSION_GRANTED) {
            MMI_LOGD("permission is not granted");
            sess->AddPermission(false);
        }
    }
}

void UDSServer::Dump(int32_t fd)
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

void UDSServer::OnConnected(SessionPtr s)
{
    MMI_LOGI("session desc:%{public}s", s->GetDescript().c_str());
}

void UDSServer::OnDisconnected(SessionPtr s)
{
    MMI_LOGI("session desc:%{public}s", s->GetDescript().c_str());
}

int32_t UDSServer::AddEpoll(EpollEventType type, int32_t fd)
{
    MMI_LOGE("This information should not exist. Subclasses should implement this function.");
    return RET_ERR;
}

void UDSServer::SetRecvFun(MsgServerFunCallback fun)
{
    recvFun_ = fun;
}

bool UDSServer::StartServer()
{
    isRunning_ = true;
    t_ = std::thread(std::bind(&UDSServer::OnThread, this));
    t_.detach();
    return true;
}

void UDSServer::OnRecv(int32_t fd, const char *buf, size_t size)
{
    CHKPV(buf);
    if (fd < 0) {
        MMI_LOGE("The fd less than 0, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
    auto sess = GetSession(fd);
    CHKPV(sess);
    int32_t readIdx = 0;
    int32_t packSize = 0;
    int32_t bufSize = static_cast<int32_t>(size);
    const int32_t headSize = static_cast<int32_t>(sizeof(PackHead));
    if (bufSize < headSize) {
        MMI_LOGE("The in parameter size less than headSize, errCode%{public}d", VAL_NOT_EXP);
        return;
    }
    while (bufSize > 0 && recvFun_) {
        if (bufSize < headSize) {
            MMI_LOGE("The size less than headSize, errCode%{public}d", VAL_NOT_EXP);
            return;
        }
        auto head = (PackHead*)&buf[readIdx];
        if (head->size[0] >= bufSize) {
            MMI_LOGE("The head->size[0] more or equal than size, errCode:%{public}d", VAL_NOT_EXP);
            return;
        }
        packSize = headSize + head->size[0];
        if (bufSize < packSize) {
            MMI_LOGE("The size less than packSize, errCode:%{public}d", VAL_NOT_EXP);
            return;
        }
        
        NetPacket pkt(head->idMsg);
        if (head->size[0] > 0) {
            if (!pkt.Write(&buf[readIdx + headSize], static_cast<size_t>(head->size[0]))) {
                MMI_LOGE("Write to the stream failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
                return;
            }
        }
        recvFun_(sess, pkt);
        bufSize -= packSize;
        readIdx += packSize;
    }
}

void UDSServer::OnEpollRecv(int32_t fd, const char *buf, size_t size)
{
    OnRecv(fd, buf, size);
}

void UDSServer::OnEvent(const struct epoll_event& ev, std::map<int32_t, StreamBufData>& bufMap)
{
    constexpr size_t maxCount = MAX_STREAM_BUF_SIZE / MAX_PACKET_BUF_SIZE + 1;
    if (maxCount <= 0) {
        MMI_LOGE("The maxCount value is error, errCode:%{public}d", VAL_NOT_EXP);
        return;
    }
    auto fd = ev.data.fd;
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_LOGD("fd:%{public}d,ev.events:0x%{public}x", fd, ev.events);
        auto secPtr = GetSession(fd);
        if (secPtr) {
            OnDisconnected(secPtr);
            DelSession(fd);
        }
        close(fd);
        return;
    }

    if (fd != IMultimodalInputConnect::INVALID_SOCKET_FD && (ev.events & EPOLLIN)) {
        auto bufData = &bufMap[fd];
        if (bufData->isOverflow) {
            MMI_LOGE("StreamBuffer full or write error, Data discarded errCode:%{public}d",
                STREAMBUFF_OVER_FLOW);
            return;
        }
        char szBuf[MAX_PACKET_BUF_SIZE] = {};
        for (size_t j = 0; j < maxCount; j++) {
            auto size = read(fd, (void*)szBuf, MAX_PACKET_BUF_SIZE);
#ifdef OHOS_BUILD_HAVE_DUMP_DATA
            DumpData(szBuf, size, LINEINFO, "in %s, read message from fd: %d.", __func__, fd);
#endif
            if (size > 0 && bufData->sBuf.Write(szBuf, size) == false) {
                bufData->isOverflow = true;
                break;
            }
            if (size < MAX_PACKET_BUF_SIZE) {
                break;
            }
        }
    }
}

void UDSServer::OnEpollEvent(std::map<int32_t, StreamBufData>& bufMap, struct epoll_event& ev)
{
    constexpr size_t maxCount = MAX_STREAM_BUF_SIZE / MAX_PACKET_BUF_SIZE + 1;
    if (maxCount <= 0) {
        MMI_LOGE("The maxCount value is error, errCode:%{public}d", VAL_NOT_EXP);
        return;
    }
    CHKPV(ev.data.ptr);
    auto fd = *static_cast<int32_t*>(ev.data.ptr);
    if (fd < 0) {
        MMI_LOGE("The fd less than 0, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_LOGD("EPOLLERR or EPOLLHUP fd:%{public}d,ev.events:0x%{public}x", fd, ev.events);
        auto secPtr = GetSession(fd);
        if (secPtr != nullptr) {
            OnDisconnected(secPtr);
            DelSession(fd);
        }
        free(ev.data.ptr);
        ev.data.ptr = nullptr;
        close(fd);
    } else if (ev.events & EPOLLIN) {
        auto bufData = &bufMap[fd];
        if (bufData->isOverflow) {
            MMI_LOGE("StreamBuffer full or write error, Data discarded errCode:%{public}d",
                STREAMBUFF_OVER_FLOW);
            return;
        }
        char szBuf[MAX_PACKET_BUF_SIZE] = {};
        for (size_t j = 0; j < maxCount; j++) {
            auto size = read(fd, (void*)szBuf, MAX_PACKET_BUF_SIZE);
#ifdef OHOS_BUILD_HAVE_DUMP_DATA
            DumpData(szBuf, size, LINEINFO, "in %s, read message from fd: %d.", __func__, fd);
#endif
            if (size > 0 && bufData->sBuf.Write(szBuf, size) == false) {
                bufData->isOverflow = true;
                break;
            }
            if (size < MAX_PACKET_BUF_SIZE) {
                break;
            }
        }
    }
}

void UDSServer::DumpSession(const std::string &title)
{
    MMI_LOGD("in %s: %s", __func__, title.c_str());
    int32_t i = 0;
    for (auto& r : sessionsMap_) {
        MMI_LOGD("%d, %s", i, r.second->GetDescript().c_str());
        i++;
    }
}

SessionPtr UDSServer::GetSession(int32_t fd) const
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

bool UDSServer::AddSession(SessionPtr ses)
{
    CHKPF(ses);
    MMI_LOGD("pid:%{public}d,fd:%{public}d", ses->GetPid(), ses->GetFd());
    auto fd = ses->GetFd();
    if (fd < 0) {
        MMI_LOGE("fd is less than 0");
        return false;
    }
    auto pid = ses->GetPid();
    if (pid <= 0) {
        MMI_LOGE("Get process faild");
        return false;
    }
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

void UDSServer::DelSession(int32_t fd)
{
    CALL_LOG_ENTER;
    MMI_LOGD("fd:%{public}d", fd);
    if (fd < 0) {
        MMI_LOGE("The fd less than 0, errCode:%{public}d", PARAM_INPUT_INVALID);
        return;
    }
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
}

void UDSServer::OnThread()
{
    CALL_LOG_ENTER;
    SetThreadName(std::string("uds_server"));
    uint64_t tid = GetThisThreadIdOfLL();
    if (tid <= 0) {
        MMI_LOGE("The tid value is error, errCode:%{public}d", VAL_NOT_EXP);
        return;
    }
    MMI_LOGD("tid:%{public}" PRId64 "", tid);

    std::map<int32_t, StreamBufData> bufMap;
    struct epoll_event ev[MAX_EVENT_SIZE] = {};
    while (isRunning_) {
        auto count = EpollWait(*ev, MAX_EVENT_SIZE, DEFINE_EPOLL_TIMEOUT);
        if (count > 0) {
            bufMap.clear();
            for (auto i = 0; i < count; i++) {
                OnEvent(ev[i], bufMap);
            }
            for (const auto &item : bufMap) {
                if (item.second.isOverflow) {
                    continue;
                }
                OnRecv(item.first, item.second.sBuf.Data(), item.second.sBuf.Size());
            }
        }
    }
}

void UDSServer::AddSessionDeletedCallback(std::function<void(SessionPtr)> callback)
{
    CALL_LOG_ENTER;
    callbacks_.push_back(callback);
}

void UDSServer::NotifySessionDeleted(SessionPtr ses)
{
    CALL_LOG_ENTER;
    for (const auto& callback : callbacks_) {
        callback(ses);
    }
}
} // namespace MMI
} // namespace OHOS