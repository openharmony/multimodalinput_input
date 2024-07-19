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

#ifndef STATIONARY_PARAMS_H
#define STATIONARY_PARAMS_H

#include "intention_identity.h"
#include "stationary_callback.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
enum StationaryRequestID : uint32_t {
    UNKNOWN_STATIONARY_REQUEST,
    SUBSCRIBE_STATIONARY,
    UNSUBSCRIBE_STATIONARY,
    GET_STATIONARY_DATA,
};

struct SubscribeStationaryParam final : public ParamBase {
    SubscribeStationaryParam() = default;
    SubscribeStationaryParam(Type type, ActivityEvent event,
        ReportLatencyNs latency, sptr<IRemoteDevStaCallback> callback);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    Type type_;
    ActivityEvent event_;
    ReportLatencyNs latency_;
    sptr<IRemoteDevStaCallback> callback_;
};

using UnsubscribeStationaryParam = SubscribeStationaryParam;

struct GetStaionaryDataParam final : public ParamBase {
    GetStaionaryDataParam() = default;
    explicit GetStaionaryDataParam(Type type);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    Type type_ { Type::TYPE_INVALID };
};

struct GetStaionaryDataReply final : public ParamBase {
    GetStaionaryDataReply() = default;
    explicit GetStaionaryDataReply(Data data);

    bool Marshalling(MessageParcel &parcel) const override;
    bool Unmarshalling(MessageParcel &parcel) override;

    Data data_ {};
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // STATIONARY_PARAMS_H
