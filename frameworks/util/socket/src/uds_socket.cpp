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
#include "uds_socket.h"
#include <inttypes.h>
#include "log.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "UDSSocket" };
    }
}

OHOS::MMI::UDSSocket::UDSSocket()
{
}

OHOS::MMI::UDSSocket::~UDSSocket()
{
    Close();
}

int32_t OHOS::MMI::UDSSocket::Close()
{
    int rf = RET_OK;
    if (fd_ >= 0) {
        rf = close(fd_);
        if (rf > 0) {
            MMI_LOGE("Socket close failed rf:%{public}d", rf);
        }
    }
    fd_ = -1;
    return rf;
}

size_t OHOS::MMI::UDSSocket::Read(char *buf, size_t size)
{
    CHKR(buf, NULL_POINTER, -1);
    CHKR(size > 0, PARAM_INPUT_INVALID, -1);
    CHKR(fd_ >= 0, PARAM_INPUT_INVALID, -1);
    uint64_t ret = read(fd_, static_cast<void *>(buf), size);
    if (ret < 0) {
        MMI_LOGE("UDSSocket::Read read return %{public}" PRId64 "", ret);
    }
    return ret;
}

size_t OHOS::MMI::UDSSocket::Write(const char *buf, size_t size)
{
    CHKR(buf, NULL_POINTER, -1);
    CHKR(size > 0, PARAM_INPUT_INVALID, -1);
    CHKR(fd_ >= 0, PARAM_INPUT_INVALID, -1);
    uint64_t ret = write(fd_, buf, size);
    if (ret < 0) {
        MMI_LOGE("UDSSocket::Write write return %{public}" PRId64 "", ret);
    }
    return ret;
}

size_t OHOS::MMI::UDSSocket::Send(const char *buf, size_t size, int32_t flags)
{
    CHKR(buf, NULL_POINTER, -1);
    CHKR(size > 0, PARAM_INPUT_INVALID, -1);
    uint64_t ret = send(fd_, buf, size, flags);
    if (ret < 0) {
        MMI_LOGE("UDSSocket::Send send return %{public}" PRId64 "", ret);
    }
    return ret;
}

size_t OHOS::MMI::UDSSocket::Recv(char *buf, size_t size, int32_t flags)
{
    CHKR(buf, NULL_POINTER, -1);
    CHKR(size > 0, PARAM_INPUT_INVALID, -1);
    uint64_t ret = recv(fd_, static_cast<void *>(buf), size, flags);
    if (ret < 0) {
        MMI_LOGE("UDSSocket::Recv recv return %{public}" PRId64 "", ret);
    }
    return ret;
}

size_t OHOS::MMI::UDSSocket::Recvfrom(char *buf, size_t size, uint32_t flags, sockaddr *addr, size_t *addrlen)
{
    CHKR(buf, NULL_POINTER, -1);
    CHKR(size > 0, PARAM_INPUT_INVALID, -1);
    CHKR(fd_ >= 0, PARAM_INPUT_INVALID, -1);
    uint64_t ret = recvfrom(fd_, static_cast<void *>(buf), size, flags, addr, reinterpret_cast<socklen_t *>(addrlen));
    if (ret < 0) {
        MMI_LOGE("UDSSocket::Recvfrom recvfrom return %{public}" PRId64 "", ret);
    }
    return ret;
}

size_t OHOS::MMI::UDSSocket::Sendto(const char *buf, size_t size, uint32_t flags, sockaddr *addr, size_t addrlen)
{
    CHKR(buf, NULL_POINTER, -1);
    CHKR(size > 0, PARAM_INPUT_INVALID, -1);
    CHKR(fd_ >= 0, PARAM_INPUT_INVALID, -1);
    uint64_t ret = sendto(fd_, static_cast<const void *>(buf), size, flags, addr, static_cast<socklen_t>(addrlen));
    if (ret < 0) {
        MMI_LOGE("UDSSocket::Sendto sendto return %{public}" PRId64 "", ret);
    }
    return ret;
}

int32_t OHOS::MMI::UDSSocket::EpollCreat(int32_t size)
{
    epollFd_ = epoll_create(size);
    if (epollFd_ < 0) {
        MMI_LOGE("UDSSocket::EpollCreat epoll_create retrun %{public}d", epollFd_);
    } else {
        MMI_LOGI("UDSSocket::EpollCreat epoll_create, epollFd_ = %{public}d", epollFd_);
    }
    return epollFd_;
}

int32_t OHOS::MMI::UDSSocket::EpollCtl(int32_t fd, int32_t op, epoll_event& event)
{
    CHKR(epollFd_ >= 0, PARAM_INPUT_INVALID, RET_ERR);
    CHKR(fd >= 0, PARAM_INPUT_INVALID, RET_ERR);
    auto ret = epoll_ctl(epollFd_, op, fd, &event);
    if (ret < 0) {
        const int errnoSaved = errno;
        MMI_LOGE("UDSSocket::EpollCtl epoll_ctl retrun %{public}d epollFd_:%{public}d,"
                 " op:%{public}d fd:%{public}d errno:%{public}d error msg: %{public}s",
                 ret, epollFd_, op, fd, errnoSaved, strerror(errnoSaved));
    }
    return ret;
}

int32_t OHOS::MMI::UDSSocket::EpollWait(epoll_event& events, int32_t maxevents, int32_t timeout)
{
    CHKR(epollFd_ >= 0, PARAM_INPUT_INVALID, RET_ERR);
    auto ret = epoll_wait(epollFd_, &events, maxevents, timeout);
    if (ret < 0) {
        MMI_LOGE("UDSSocket::EpollWait epoll_wait retrun %{public}d", ret);
    }
    return ret;
}

void OHOS::MMI::UDSSocket::EpollClose()
{
    if (epollFd_ >= 0) {
        close(epollFd_);
        epollFd_ = -1;
    }
}
