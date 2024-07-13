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

#ifndef COOPERATE_PARAMS_H
#define COOPERATE_PARAMS_H

#include <string>

#include "intention_identity.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum CooperateRequestID : uint32_t {
    UNKNOWN_COOPERATE_ACTION,
    REGISTER_LISTENER,
    UNREGISTER_LISTENER,
    REGISTER_HOTAREA_LISTENER,
    UNREGISTER_HOTAREA_LISTENER,
    GET_COOPERATE_STATE,
    GET_COOPERATE_STATE_SYNC,
    REGISTER_EVENT_LISTENER,
    UNREGISTER_EVENT_LISTENER,
};

struct StartCooperateParam final : public ParamBase {
    StartCooperateParam() = default;
    StartCooperateParam(int32_t userData, const std::string &remoteNetworkId,
                        int32_t startDeviceId, bool checkPermission);
    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::string remoteNetworkId;
    int32_t userData { -1 };
    int32_t startDeviceId { -1 };
    bool checkPermission { false };
};

struct StopCooperateParam final : public ParamBase {
    StopCooperateParam() = default;
    StopCooperateParam(int32_t userData, bool isUnchained, bool checkPermission);
    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    int32_t userData { -1 };
    bool isUnchained { false };
    bool checkPermission { false };
};

struct GetCooperateStateParam final : public ParamBase {
    GetCooperateStateParam() = default;
    GetCooperateStateParam(int32_t userData, const std::string &networkId, bool checkPermission);
    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::string networkId;
    int32_t userData { -1 };
    bool checkPermission { false };
};

struct RegisterEventListenerParam final : public ParamBase {
    RegisterEventListenerParam() = default;
    RegisterEventListenerParam(const std::string &networkId);
    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;
    std::string networkId;
};

using UnregisterEventListenerParam = RegisterEventListenerParam;

struct GetCooperateStateSyncParam final : public ParamBase {
    GetCooperateStateSyncParam() = default;
    GetCooperateStateSyncParam(const std::string &udId);
    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    std::string udId;
};

struct RegisterHotAreaListenerParam final : public ParamBase {
    RegisterHotAreaListenerParam() = default;
    RegisterHotAreaListenerParam(int32_t userData, bool checkPermission);
    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;
    int32_t userData { -1 };
    bool checkPermission { false };
};

using UnregisterHotAreaListenerParam = RegisterHotAreaListenerParam;

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_PARAMS_H
