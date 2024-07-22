/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef I_EPOLL_EVENT_SOURCE_H
#define I_EPOLL_EVENT_SOURCE_H

#include <sys/epoll.h>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IEpollEventSource {
public:
    IEpollEventSource() = default;
    virtual ~IEpollEventSource() = default;

    virtual uint32_t GetEvents() const;
    virtual int32_t GetFd() const = 0;
    virtual void Dispatch(const struct epoll_event &ev) = 0;
};

inline uint32_t IEpollEventSource::GetEvents() const
{
    return (EPOLLIN | EPOLLHUP | EPOLLERR);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_EPOLL_EVENT_SOURCE_H