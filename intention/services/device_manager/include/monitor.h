/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef MONITOR_H
#define MONITOR_H

#include <memory>
#include <set>

#include <sys/inotify.h>

#include "nocopyable.h"

#include "i_context.h"
#include "i_device_mgr.h"
#include "i_epoll_event_source.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class Monitor final : public IEpollEventSource {
public:
    Monitor() = default;
    DISALLOW_COPY_AND_MOVE(Monitor);
    ~Monitor();

    int32_t GetFd() const override;
    void Dispatch(const struct epoll_event &ev) override;
    void SetDeviceMgr(IDeviceMgr *devMgr);
    int32_t Enable();
    void Disable();

private:
    int32_t OpenConnection();
    int32_t EnableReceiving();
    void ReceiveDevice();
    void HandleInotifyEvent(struct inotify_event *event) const;
    void AddDevice(const std::string &devNode) const;
    void RemoveDevice(const std::string &devNode) const;

private:
    int32_t inotifyFd_ { -1 };
    int32_t devWd_ { -1 };
    IDeviceMgr *devMgr_ { nullptr };
};

inline int32_t Monitor::GetFd() const
{
    return inotifyFd_;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // MONITOR_H