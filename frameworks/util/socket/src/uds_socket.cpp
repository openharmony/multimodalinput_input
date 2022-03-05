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

#include "uds_socket.h"
#include <cinttypes>
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UDSSocket" };
    }

UDSSocket::UDSSocket() {}

UDSSocket::~UDSSocket()
{
    Close();
    EpollClose();
}

int32_t UDSSocket::EpollCreat(int32_t size)
{
    epollFd_ = epoll_create(size);
    if (epollFd_ < 0) {
        MMI_LOGE("epoll_create retrun %{public}d", epollFd_);
    } else {
        MMI_LOGI("epoll_create, epollFd_:%{public}d", epollFd_);
    }
    return epollFd_;
}

int32_t UDSSocket::EpollCtl(int32_t fd, int32_t op, struct epoll_event& event, int32_t epollFd)
{
    if (fd < 0) {
        MMI_LOGE("Invalid fd");
        return RET_ERR;
    }
    if (epollFd < 0) {
        epollFd = epollFd_;
    }
    if (epollFd < 0) {
        MMI_LOGE("Invalid param epollFd");
        return RET_ERR;
    }
    auto ret = epoll_ctl(epollFd, op, fd, &event);
    if (ret < 0) {
        const int32_t errnoSaved = errno;
        MMI_LOGE("epoll_ctl retrun %{public}d,epollFd_:%{public}d,"
                 "op:%{public}d,fd:%{public}d,errno:%{public}d,error msg: %{public}s",
                 ret, epollFd, op, fd, errnoSaved, strerror(errnoSaved));
    }
    return ret;
}

int32_t UDSSocket::EpollWait(struct epoll_event& events, int32_t maxevents, int32_t timeout, int32_t epollFd)
{
    if (epollFd < 0) {
        epollFd = epollFd_;
    }
    if (epollFd < 0) {
        MMI_LOGE("Invalid param epollFd");
        return RET_ERR;
    }
    auto ret = epoll_wait(epollFd, &events, maxevents, timeout);
    if (ret < 0) {
        const int errnoSaved = errno;
        MMI_LOGE("epoll_wait retrun %{public}d,errno:%{public}d,%{public}s",
            ret, errnoSaved, strerror(errnoSaved));
    }
    return ret;
}

int32_t UDSSocket::SetBlockMode(int32_t fd, bool isBlock)
{
    if (fd < 0) {
        MMI_LOGE("Invalid fd");
        return RET_ERR;
    }
    int32_t flags = fcntl(fd, F_GETFL);
    if (flags < 0) {
        MMI_LOGE("fcntl F_GETFL fail. fd:%{public}d,flags:%{public}d,msg:%{public}s,errCode:%{public}d",
            fd, flags, strerror(errno), FCNTL_FAIL);
        return flags;
    }
    MMI_LOGD("F_GETFL fd:%{public}d,flags:%{public}d", fd, flags);
    flags |= O_NONBLOCK; // 非阻塞模式
    if (isBlock) {
        flags &= ~O_NONBLOCK; // 阻塞模式
    }
    flags = fcntl(fd, F_SETFL, flags);
    if (flags < 0) {
        MMI_LOGE("fcntl F_SETFL fail. fd:%{public}d,flags:%{public}d,msg:%{public}s,errCode:%{public}d",
            fd, flags, strerror(errno), FCNTL_FAIL);
        return flags;
    }
    MMI_LOGD("F_SETFL fd:%{public}d,flags:%{public}d", fd, flags);
    return flags;
}

void UDSSocket::EpollClose()
{
    if (epollFd_ >= 0) {
        close(epollFd_);
        epollFd_ = -1;
    }
}

size_t UDSSocket::Read(char *buf, size_t size)
{
    CHKPR(buf, -1);
    if (size <= 0) {
        MMI_LOGE("Invalid param size");
        return -1;
    }
    if (fd_ < 0) {
        MMI_LOGE("Invalid param fd_");
        return -1;
    }
    ssize_t ret = read(fd_, static_cast<void *>(buf), size);
    if (ret < 0) {
        MMI_LOGE("read return %{public}zd", ret);
    }
    return ret;
}

size_t UDSSocket::Write(const char *buf, size_t size)
{
    CHKPR(buf, -1);
    if (size <= 0) {
        MMI_LOGE("Invalid param size");
        return -1;
    }
    if (fd_ < 0) {
        MMI_LOGE("Invalid param fd_");
        return -1;
    }
    ssize_t ret = write(fd_, buf, size);
    if (ret < 0) {
        MMI_LOGE("write return %{public}zd", ret);
    }
    return ret;
}

size_t UDSSocket::Send(const char *buf, size_t size, int32_t flags)
{
    CHKPR(buf, -1);
    if (size <= 0) {
        MMI_LOGE("Invalid param size");
        return -1;
    }
    ssize_t ret = send(fd_, buf, size, flags);
    if (ret < 0) {
        MMI_LOGE("send return %{public}zd", ret);
    }
    return ret;
}

size_t UDSSocket::Recv(char *buf, size_t size, int32_t flags)
{
    CHKPR(buf, -1);
    if (size <= 0) {
        MMI_LOGE("Invalid param size");
        return -1;
    }
    ssize_t ret = recv(fd_, static_cast<void *>(buf), size, flags);
    if (ret < 0) {
        MMI_LOGE("recv return %{public}zd", ret);
    }
    return ret;
}

size_t UDSSocket::Recvfrom(char *buf, size_t size, uint32_t flags, sockaddr *addr, size_t *addrlen)
{
    CHKPR(buf, -1);
    if (size <= 0) {
        MMI_LOGE("Invalid param size");
        return -1;
    }
    if (fd_ < 0) {
        MMI_LOGE("Invalid param fd_");
        return -1;
    }
    ssize_t ret = recvfrom(fd_, static_cast<void *>(buf), size, flags, addr, reinterpret_cast<socklen_t *>(addrlen));
    if (ret < 0) {
        MMI_LOGE("recvfrom return %{public}zd", ret);
    }
    return ret;
}

size_t UDSSocket::Sendto(const char *buf, size_t size, uint32_t flags, sockaddr *addr, size_t addrlen)
{
    CHKPR(buf, -1);
    if (size <= 0) {
        MMI_LOGE("Invalid param size");
        return -1;
    }
    if (fd_ < 0) {
        MMI_LOGE("Invalid param fd_");
        return -1;
    }
    ssize_t ret = sendto(fd_, static_cast<const void *>(buf), size, flags, addr, static_cast<socklen_t>(addrlen));
    if (ret < 0) {
        MMI_LOGE("sendto return %{public}zd", ret);
    }
    return ret;
}

void UDSSocket::Close()
{
    if (fd_ >= 0) {
        auto rf = close(fd_);
        if (rf > 0) {
            MMI_LOGE("Socket close failed rf:%{public}d", rf);
        }
    }
    fd_ = -1;
}
} // namespace MMI
} // namespace OHOS