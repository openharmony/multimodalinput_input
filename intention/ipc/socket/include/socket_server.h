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

#ifndef SOCKET_SERVER_H
#define SOCKET_SERVER_H

#include "nocopyable.h"

#include "i_context.h"
#include "i_plugin.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class SocketServer final : public IPlugin {
public:
    SocketServer(IContext *context);
    ~SocketServer() = default;
    DISALLOW_COPY_AND_MOVE(SocketServer);

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
    IContext *context_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // SOCKET_SERVER_H
