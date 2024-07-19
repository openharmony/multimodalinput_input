/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef INTENTION_STATIONARY_CLIENT_H
#define INTENTION_STATIONARY_CLIENT_H

#include <map>

#include "nocopyable.h"

#include "i_tunnel_client.h"
#include "stationary_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class StationaryClient final {
public:
    StationaryClient() = default;
    ~StationaryClient() = default;
    DISALLOW_COPY_AND_MOVE(StationaryClient);

    int32_t SubscribeCallback(ITunnelClient &tunnel, Type type, ActivityEvent event,
        ReportLatencyNs latency, sptr<IRemoteDevStaCallback> callback);
    int32_t UnsubscribeCallback(ITunnelClient &tunnel, Type type, ActivityEvent event,
        sptr<IRemoteDevStaCallback> callback);
    Data GetDeviceStatusData(ITunnelClient &tunnel, Type type);

private:
    std::mutex mtx_;
    std::map<Type, int32_t> typeMap_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTENTION_STATIONARY_CLIENT_H
