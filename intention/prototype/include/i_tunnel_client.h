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

// Implementation of client side of IPC.

#ifndef I_TUNNEL_CLIENT_H
#define I_TUNNEL_CLIENT_H

#include "intention_identity.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

class ITunnelClient {
public:
    virtual ~ITunnelClient() = default;

    // Request to enable the service identified by [`intention`].
    virtual int32_t Enable(Intention intention, ParamBase &data, ParamBase &reply) = 0;
    // Request to disable the service identified by [`intention`].
    virtual int32_t Disable(Intention intention, ParamBase &data, ParamBase &reply) = 0;
    // Request to start the service identified by [`intention`].
    virtual int32_t Start(Intention intention, ParamBase &data, ParamBase &reply) = 0;
    // Request to stop the service identified by [`intention`].
    virtual int32_t Stop(Intention intention, ParamBase &data, ParamBase &reply) = 0;
    // Request to add a watch of state of service, with the service identified by
    // [`intention`], the state to watch identified by [`id`], parameters packed in
    // [`data`] parcel.
    virtual int32_t AddWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
    // Request to remove a watch of state of service.
    virtual int32_t RemoveWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
    // Request to set a parameter of service, with the service identified by
    // [`intention`], the parameter identified by [`id`], and values packed in
    // [`data`] parcel.
    virtual int32_t SetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
    // Request to get a parameter of service, with the service identified by
    // [`intention`], the parameter identified by [`id`].
    virtual int32_t GetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
    // Request to interact with service identified by [`intention`] for general purpose.
    // This interface supplements functions of previous intefaces. Functionalities of
    // this interface is service spicific.
    virtual int32_t Control(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_TUNNEL_CLIENT_H
