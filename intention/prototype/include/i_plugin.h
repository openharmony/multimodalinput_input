/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef I_PLUGIN_H
#define I_PLUGIN_H

#include "intention_identity.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
struct CallingContext {
    Intention intention { Intention::UNKNOWN_INTENTION };
    uint64_t fullTokenId { 0 };
    uint32_t tokenId { 0 };
    int32_t uid { -1 };
    int32_t pid { -1 };
};

class IPlugin {
public:
    IPlugin() = default;
    virtual ~IPlugin() = default;

    virtual int32_t Enable(CallingContext &context, MessageParcel &data, MessageParcel &reply) = 0;
    virtual int32_t Disable(CallingContext &context, MessageParcel &data, MessageParcel &reply) = 0;
    virtual int32_t Start(CallingContext &context, MessageParcel &data, MessageParcel &reply) = 0;
    virtual int32_t Stop(CallingContext &context, MessageParcel &data, MessageParcel &reply) = 0;
    virtual int32_t AddWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;
    virtual int32_t RemoveWatch(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;
    virtual int32_t SetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;
    virtual int32_t GetParam(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;
    virtual int32_t Control(CallingContext &context, uint32_t id, MessageParcel &data, MessageParcel &reply) = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_PLUGIN_H
