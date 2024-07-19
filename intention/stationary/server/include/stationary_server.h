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

#ifndef STATIONARY_SERVER_H
#define STATIONARY_SERVER_H

#include "nocopyable.h"

#include "devicestatus_manager.h"
#include "i_plugin.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class StationaryServer final : public IPlugin {
public:
    StationaryServer();
    ~StationaryServer() = default;
    DISALLOW_COPY_AND_MOVE(StationaryServer);

    int32_t Enable(CallingContext &context, MessageParcel &data, MessageParcel &reply) override;
    int32_t Disable(CallingContext &context, MessageParcel &data, MessageParcel &reply) override;
    int32_t Start(CallingContext &context, MessageParcel &data, MessageParcel &reply) override;
    int32_t Stop(CallingContext &context, MessageParcel &data, MessageParcel &reply) override;
    int32_t AddWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t RemoveWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t SetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t GetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;
    int32_t Control(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) override;

private:
    void Subscribe(CallingContext &context, Type type, ActivityEvent event,
        ReportLatencyNs latency, sptr<IRemoteDevStaCallback> callback);
    void Unsubscribe(CallingContext &context, Type type, ActivityEvent event,
        sptr<IRemoteDevStaCallback> callback);
    Data GetCache(CallingContext &context, const Type &type);
    void ReportSensorSysEvent(CallingContext &context, int32_t type, bool enable);

    DeviceStatusManager manager_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // STATIONARY_SERVER_H