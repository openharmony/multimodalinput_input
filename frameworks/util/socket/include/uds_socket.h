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
#ifndef OHOS_UDS_SOCKET_H
#define OHOS_UDS_SOCKET_H

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <atomic>
#include <string>
#include "libmmi_util.h"

namespace OHOS {
namespace MMI {
class UDSSocket {
public:
    UDSSocket();
    virtual ~UDSSocket();

    virtual int32_t Socket() = 0;
    virtual int32_t Close();

    virtual int32_t EpollCreat(int32_t size);
    virtual int32_t EpollCtl(int32_t fd, int32_t op, epoll_event& event);
    virtual int32_t EpollWait(epoll_event& events, int32_t maxevents, int32_t timeout);
    virtual void EpollClose();

    int32_t GetFd() const
    {
        return fd_;
    }
    int32_t GetEpollFd() const
    {
        return epollFd_;
    }

protected:
    virtual size_t Read(char *buf, size_t size);
    virtual size_t Write(const char *buf, size_t size);
    virtual size_t Send(const char *buf, size_t size, int32_t flags);
    virtual size_t Recv(char *buf, size_t size, int32_t flags);
    virtual size_t Recvfrom(char *buf, size_t size, uint32_t flags, sockaddr *addr, size_t *addrlen);
    virtual size_t Sendto(const char *buf, size_t size, uint32_t flags, sockaddr *addr, size_t addrlen);

protected:
    int32_t fd_ = -1;
    int32_t epollFd_ = -1;
};
}
}
#endif
