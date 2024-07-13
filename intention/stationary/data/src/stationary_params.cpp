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

#include "stationary_params.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

SubscribeStationaryParam::SubscribeStationaryParam(Type type, ActivityEvent event,
    ReportLatencyNs latency, sptr<IRemoteDevStaCallback> callback)
    : type_(type), event_(event), latency_(latency), callback_(callback)
{}

bool SubscribeStationaryParam::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteInt32(type_) &&
        parcel.WriteInt32(event_) &&
        parcel.WriteInt32(latency_) &&
        (callback_ != nullptr) &&
        parcel.WriteRemoteObject(callback_->AsObject())
    );
}

bool SubscribeStationaryParam::Unmarshalling(MessageParcel &parcel)
{
    int32_t type {};
    int32_t event {};
    int32_t latency {};

    bool result = parcel.ReadInt32(type) &&
                  parcel.ReadInt32(event) &&
                  parcel.ReadInt32(latency);
    if (!result) {
        return false;
    }
    type_ = static_cast<Type>(type);
    event_ = static_cast<ActivityEvent>(event);
    latency_ = static_cast<ReportLatencyNs>(latency);
    sptr<IRemoteObject> obj = parcel.ReadRemoteObject();
    if (obj == nullptr) {
        return false;
    }
    callback_ = iface_cast<IRemoteDevStaCallback>(obj);
    return (callback_ != nullptr);
}

GetStaionaryDataParam::GetStaionaryDataParam(Type type)
    : type_(type) {}

bool GetStaionaryDataParam::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteInt32(type_);
}

bool GetStaionaryDataParam::Unmarshalling(MessageParcel &parcel)
{
    int32_t type {};

    if (!parcel.ReadInt32(type)) {
        return false;
    }
    type_ = static_cast<Type>(type);
    return true;
}

GetStaionaryDataReply::GetStaionaryDataReply(Data data)
    : data_(data) {}

bool GetStaionaryDataReply::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteInt32(data_.type) &&
        parcel.WriteInt32(data_.value) &&
        parcel.WriteInt32(data_.status) &&
        parcel.WriteInt32(data_.action) &&
        parcel.WriteDouble(data_.movement)
    );
}

bool GetStaionaryDataReply::Unmarshalling(MessageParcel &parcel)
{
    int32_t type {};
    int32_t value {};
    int32_t status {};
    int32_t action {};

    bool result = parcel.ReadInt32(type) &&
                  parcel.ReadInt32(value) &&
                  parcel.ReadInt32(status) &&
                  parcel.ReadInt32(action) &&
                  parcel.ReadDouble(data_.movement);
    if (!result) {
        return false;
    }
    data_.type = static_cast<Type>(type);
    data_.value = static_cast<OnChangedValue>(value);
    data_.status = static_cast<Status>(status);
    data_.action = static_cast<Action>(action);
    return true;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS