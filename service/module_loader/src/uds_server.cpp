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

#include "uds_server.h"
#include <list>
#include <inttypes.h>
#include <sys/socket.h>
#include "i_multimodal_input_connect.h"
#include "log.h"
#include "multimodal_input_connect_service.h"
#include "safe_keeper.h"
#include "uds_command_queue.h"
#include "util.h"
#include "util_ex.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "UDSServer"};
    }
}
}

OHOS::MMI::UDSServer::UDSServer()
{
}

OHOS::MMI::UDSServer::~UDSServer()
{
    MMI_LOGD("enter");
    UdsStop();
    MMI_LOGD("leave");
}

void OHOS::MMI::UDSServer::UdsStop()
{
    std::lock_guard<std::mutex> lock(mux_);
    isRun_ = false;
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

int32_t OHOS::MMI::UDSServer::GetFdByPid(int32_t pid)
{
    std::lock_guard<std::mutex> lock(mux_);
    auto it = idxPidMap_.find(pid);
    if (it == idxPidMap_.end()) {
        MMI_LOGE("find fd error, Invalid input parameter pid:%{public}d, errCode:%{public}d",
            pid, SESSION_NOT_FOUND);
        return RET_ERR;
    }
    return it->second;
}

int32_t OHOS::MMI::UDSServer::GetPidByFd(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mux_);
    auto it = sessionsMap_.find(fd);
    if (it == sessionsMap_.end()) {
        MMI_LOGE("find pid error, Invalid input parameter fd:%{public}d, errCode:%{public}d",
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
    if (!ses) {
        MMI_LOGE("SendMsg fd:%{public}d not found, The message was discarded! errCode:%{public}d",
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

bool  OHOS::MMI::UDSServer::ClearDeadSessionInMap(const int serverFd, const int clientFd)
{
    auto it = sessionsMap_.find(serverFd);
    if (it != sessionsMap_.end()) {
        MMI_LOGE("The session(fd1: %{public}d) on the server side will be closed because it had in map."
            "errCode:%{public}d", serverFd, SESSION_NOT_FOUND);
        DelSession(serverFd);
    }

    it = sessionsMap_.find(clientFd);
    if (it != sessionsMap_.end()) {
        MMI_LOGE("The session(fd2:%{public}d) on the server side will be closed because it had in map."
            "errCode:%{public}d", clientFd, SESSION_NOT_FOUND);
        DelSession(clientFd);
    }
    return true;
}

int32_t OHOS::MMI::UDSServer::AddSocketPairInfo(const std::string& programName, const int moduleType, int& serverFd,
                                                const int32_t uid, const int32_t pid, int& toReturnClientFd)
{
    MMI_LOGD("enter.");
    std::lock_guard<std::mutex> lock(mux_);
    const int NUMBER_TWO = 2;
    int sockFds[NUMBER_TWO] = {};

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockFds) != 0) {
        const int savedErrNo = errno;
        MMI_LOGE("call socketpair fail, errno: %{public}d, msg: %{public}s!", savedErrNo, strerror(savedErrNo));
        return RET_ERR;
    }

    serverFd = sockFds[0];
    toReturnClientFd = sockFds[1]; // fcntl(sockFds[1], F_DUPFD_CLOEXEC, 0);
    if (toReturnClientFd < 0) {
        const int savedErrNo = errno;
        MMI_LOGE("call fcntl fail, errno: %{public}d, msg: %{public}s!", savedErrNo, strerror(savedErrNo));
        return RET_ERR;
    }

    const size_t bufferSize = 32 * 1024;
    setsockopt(sockFds[0], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sockFds[0], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sockFds[1], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof(bufferSize));
    setsockopt(sockFds[1], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof(bufferSize));
    SetBlockMode(serverFd); // 设置非阻塞模式

    MMI_LOGD("alloc socketpair, serverFd = %{public}d, clientFd = %{public}d(%{public}d).",
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
        MMI_LOGE("IsSocketFdNotUsed error! errCode:%{public}d", CLEAR_DEAD_SESSION_FAIL);
        return RET_ERR;
    }

    int32_t ret = RET_OK;
#ifdef OHOS_WESTEN_MODEL
    epoll_event nev = {};
    nev.events = EPOLLIN;
    nev.data.fd = serverFd;
    ret = EpollCtl(serverFd, EPOLL_CTL_ADD, nev);
#else
    ret = EpollCtlAdd(EPOLL_EVENT_SOCKET, serverFd);
#endif
    if (ret != RET_OK) {
        cleanTaskWhenError();
        MMI_LOGE("epoll_ctl EPOLL_CTL_ADD return %{public}d, errCode:%{public}d", ret, EPOLL_MODIFY_FAIL);
        return ret;
    }

    SessionPtr sess = std::make_shared<UDSSession>(programName, moduleType, serverFd, uid, pid);
    if (sess == nullptr) {
        cleanTaskWhenError();
        MMI_LOGE("make_shared fail. progName:%{public}s, pid:%{public}d, errCode:%{public}d",
            programName.c_str(), pid, MAKE_SHARED_FAIL);
        return RET_ERR;
    }

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

int32_t OHOS::MMI::UDSServer::EpollCtlAdd(EpollEventType type, int32_t fd)
{
    MMI_LOGE("UDSServer::EpollCtlAdd This information should not exist. Subclasses should implement this function.");
    return RET_ERR;
}

void OHOS::MMI::UDSServer::SetRecvFun(MsgServerFunCallback fun)
{
    recvFun_ = fun;
}

bool OHOS::MMI::UDSServer::StartServer()
{
    isRun_ = true;
    t_ = std::thread(std::bind(&UDSServer::OnThread, this));
    t_.detach();
    return true;
}

void OHOS::MMI::UDSServer::OnRecv(int32_t fd, const char *buf, size_t size)
{
    CHKP(buf);
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    auto sess = GetSession(fd);
    CHK(sess, ERROR_NULL_POINTER);
    int32_t readIdx = 0;
    int32_t packSize = 0;
    const auto headSize = static_cast<int32_t>(sizeof(PackHead));
    CHK(size >= headSize, VAL_NOT_EXP);
    while (size > 0 && recvFun_) {
        CHK(size >= headSize, VAL_NOT_EXP);
        auto head = (PackHead*)&buf[readIdx];
        CHK(head->size[0] < static_cast<int32_t>(size), VAL_NOT_EXP);
        packSize = headSize + head->size[0];

        NetPacket pkt(head->idMsg);
        if (head->size[0] > 0) {
            CHK(pkt.Write(&buf[readIdx + headSize], head->size[0]), STREAM_BUF_WRITE_FAIL);
        }
        recvFun_(sess, pkt);
        size -= packSize;
        readIdx += packSize;
    }
}

void OHOS::MMI::UDSServer::OnEpollRecv(int32_t fd, const char *buf, size_t size)
{
    OnRecv(fd, buf, size);
}

void OHOS::MMI::UDSServer::OnEvent(const epoll_event& ev, std::map<int32_t, StreamBufData>& bufMap)
{
    const int32_t maxCount = static_cast<int32_t>(MAX_STREAM_BUF_SIZE / MAX_PACKET_BUF_SIZE) + 1;
    CHK(maxCount > 0, VAL_NOT_EXP);
    auto fd = ev.data.fd;
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_LOGD("UDSServer::OnEvent fd:%{public}d, ev.events:0x%{public}x", fd, ev.events);
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
            MMI_LOGE("OnEvent StreamBuffer full or write error, Data discarded errCode:%{public}d",
                STREAMBUFF_OVER_FLOW);
            return;
        }
        char szBuf[MAX_PACKET_BUF_SIZE] = {};
        for (auto j = 0; j < maxCount; j++) {
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

void OHOS::MMI::UDSServer::OnEpollEvent(std::map<int32_t, StreamBufData>& bufMap, epoll_event& ev)
{
    const int32_t maxCount = static_cast<int32_t>(MAX_STREAM_BUF_SIZE / MAX_PACKET_BUF_SIZE) + 1;
    CHK(maxCount > 0, VAL_NOT_EXP);
    CHK(ev.data.ptr, ERROR_NULL_POINTER);
    auto fd = *static_cast<int32_t*>(ev.data.ptr);
    CHK(fd >= 0, INVALID_PARAM);
    if ((ev.events & EPOLLERR) || (ev.events & EPOLLHUP)) {
        MMI_LOGD("OnEpollEvent EPOLLERR or EPOLLHUP fd:%{public}d, ev.events:0x%{public}x", fd, ev.events);
        auto secPtr = GetSession(fd);
        if (secPtr) {
            OnDisconnected(secPtr);
            DelSession(fd);
        }
        free(ev.data.ptr);
        ev.data.ptr = nullptr;
        close(fd);
    } else if (ev.events & EPOLLIN) {
        auto bufData = &bufMap[fd];
        if (bufData->isOverflow) {
            MMI_LOGE("OnEpollEvent StreamBuffer full or write error, Data discarded errCode:%{public}d",
                STREAMBUFF_OVER_FLOW);
            return;
        }
        char szBuf[MAX_PACKET_BUF_SIZE] = {};
        for (auto j = 0; j < maxCount; j++) {
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

void OHOS::MMI::UDSServer::DumpSession(const std::string &title)
{
    MMI_LOGI("in %s: %s", __func__, title.c_str());
    int i = 0;
    for (auto& r : sessionsMap_) {
        MMI_LOGI("%d, %s", i, r.second->GetDescript().c_str());
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
    MMI_LOGD("AddSession pid:%{public}d, fd:%{public}d", ses->GetPid(), ses->GetFd());
    auto fd = ses->GetFd();
    CHKF(fd >= 0, VAL_NOT_EXP);
    auto pid = ses->GetPid();
    CHKF(pid > 0, VAL_NOT_EXP);
    idxPidMap_[pid] = fd;
    sessionsMap_[fd] = ses;
    DumpSession("AddSession");
    if (sessionsMap_.size() > MAX_SESSON_ALARM) {
        MMI_LOGW("Too many clients. Warning Value:%{public}d, Current Value:%{public}zd",
                 MAX_SESSON_ALARM, sessionsMap_.size());
    }
    MMI_LOGI("AddSession end");
    return true;
}

void OHOS::MMI::UDSServer::DelSession(int32_t fd)
{
    MMI_LOGD("DelSession begin fd:%{public}d", fd);
    CHK(fd >= 0, PARAM_INPUT_INVALID);
    auto pid = GetPidByFd(fd);
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

void OHOS::MMI::UDSServer::OnThread()
{
    OHOS::MMI::SetThreadName(std::string("uds_server"));
    uint64_t tid = GetThisThreadIdOfLL();
    CHK(tid > 0, VAL_NOT_EXP);
    MMI_LOGD("begin tid:%{public}" PRId64 "", tid);
    SafeKpr->RegisterEvent(tid, "UDSServer::_OnThread");

    std::map<int32_t, StreamBufData> bufMap;
    epoll_event ev[MAX_EVENT_SIZE] = {};
    while (isRun_) {
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
        SafeKpr->ReportHealthStatus(tid);
    }
    MMI_LOGI("end");
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

