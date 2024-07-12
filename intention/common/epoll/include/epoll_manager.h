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

#ifndef EPOLL_MANAGER_H
#define EPOLL_MANAGER_H

#include <cinttypes>
#include <memory>
#include <vector>

#include "nocopyable.h"

#include "i_epoll_event_source.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class EpollManager final : public IEpollEventSource {
public:
    EpollManager() = default;
    ~EpollManager();
    DISALLOW_COPY_AND_MOVE(EpollManager);

    int32_t Open();
    void Close();

    int32_t Add(IEpollEventSource &source);
    void Remove(IEpollEventSource &source);
    int32_t Update(IEpollEventSource &source);
    int32_t Wait(struct epoll_event *events, int32_t maxevents);
    int32_t WaitTimeout(struct epoll_event *events, int32_t maxevents, int32_t timeout);

    int32_t GetFd() const override;
    void Dispatch(const struct epoll_event &ev) override;

private:
    void DispatchOne(const struct epoll_event &ev);

private:
    int32_t epollFd_ { -1 };
};

inline int32_t EpollManager::GetFd() const
{
    return epollFd_;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // EPOLL_MANAGER_H