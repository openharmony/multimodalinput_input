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

#ifndef TUNNEL_CLIENT_H
#define TUNNEL_CLIENT_H

#include <memory>

#include "i_tunnel_client.h"
#include "i_intention.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class TunnelClient final : public ITunnelClient, public std::enable_shared_from_this<TunnelClient> {
public:
    TunnelClient() = default;
    ~TunnelClient();
    DISALLOW_COPY_AND_MOVE(TunnelClient);

    // Request to enable the service identified by [`intention`].
    int32_t Enable(Intention intention, ParamBase &data, ParamBase &reply) override;
    // Request to disable the service identified by [`intention`].
    int32_t Disable(Intention intention, ParamBase &data, ParamBase &reply) override;
    // Request to start the service identified by [`intention`].
    int32_t Start(Intention intention, ParamBase &data, ParamBase &reply) override;
    // Request to stop the service identified by [`intention`].
    int32_t Stop(Intention intention, ParamBase &data, ParamBase &reply) override;
    // Request to add a watch of state of service, with the service identified by
    // [`intention`], the state to watch identified by [`id`], parameters packed in
    // [`data`] parcel.
    int32_t AddWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) override;
    // Request to remove a watch of state of service.
    int32_t RemoveWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) override;
    // Request to set a parameter of service, with the service identified by
    // [`intention`], the parameter identified by [`id`], and values packed in
    // [`data`] parcel.
    int32_t SetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) override;
    // Request to get a parameter of service, with the service identified by
    // [`intention`], the parameter identified by [`id`].
    int32_t GetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) override;
    // Request to interact with service identified by [`intention`] for general purpose.
    // This interface supplements functions of previous intefaces. Functionalities of
    // this interface is service spicific.
    int32_t Control(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply) override;

private:
    class DeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        DeathRecipient(std::shared_ptr<TunnelClient> parent);
        ~DeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &remote);

    private:
        std::weak_ptr<TunnelClient> parent_;
    };

    ErrCode Connect();
    void ResetProxy(const wptr<IRemoteObject> &remote);

private:
    std::mutex mutex_;
    sptr<IIntention> devicestatusProxy_ { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ { nullptr };
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // TUNNEL_CLIENT_H
