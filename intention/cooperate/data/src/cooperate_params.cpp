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

#include "cooperate_params.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

StartCooperateParam::StartCooperateParam(int32_t userData, const std::string &remoteNetworkId,
                                         int32_t startDeviceId, bool checkPermission)
    : remoteNetworkId(remoteNetworkId), userData(userData),
      startDeviceId(startDeviceId), checkPermission(checkPermission)
{}

bool StartCooperateParam::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteString(remoteNetworkId) &&
        parcel.WriteInt32(startDeviceId) &&
        parcel.WriteInt32(userData) &&
        parcel.WriteBool(checkPermission)
    );
}

bool StartCooperateParam::Unmarshalling(MessageParcel &parcel)
{
    return (
        parcel.ReadString(remoteNetworkId) &&
        parcel.ReadInt32(startDeviceId) &&
        parcel.ReadInt32(userData) &&
        parcel.ReadBool(checkPermission)
    );
}

StopCooperateParam::StopCooperateParam(int32_t userData, bool isUnchained, bool checkPermission)
    : userData(userData), isUnchained(isUnchained), checkPermission(checkPermission)
{}

bool StopCooperateParam::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteBool(isUnchained) &&
        parcel.WriteBool(checkPermission) &&
        parcel.WriteInt32(userData)
    );
}

bool StopCooperateParam::Unmarshalling(MessageParcel &parcel)
{
    return (
        parcel.ReadBool(isUnchained) &&
        parcel.ReadBool(checkPermission) &&
        parcel.ReadInt32(userData)
    );
}

GetCooperateStateParam::GetCooperateStateParam(int32_t userData, const std::string &networkId, bool checkPermission)
    : networkId(networkId), userData(userData), checkPermission(checkPermission)
{}

bool GetCooperateStateParam::Marshalling(MessageParcel &parcel) const
{
    return (
        parcel.WriteInt32(userData) &&
        parcel.WriteString(networkId) &&
        parcel.WriteBool(checkPermission)
    );
}

bool GetCooperateStateParam::Unmarshalling(MessageParcel &parcel)
{
    return (
        parcel.ReadInt32(userData) &&
        parcel.ReadString(networkId) &&
        parcel.ReadBool(checkPermission)
    );
}

RegisterEventListenerParam::RegisterEventListenerParam(const std::string &networkId) : networkId(networkId)
{}

bool RegisterEventListenerParam::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteString(networkId);
}

bool RegisterEventListenerParam::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadString(networkId);
}

GetCooperateStateSyncParam::GetCooperateStateSyncParam(const std::string &udId) : udId(udId)
{}

bool GetCooperateStateSyncParam::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteString(udId);
}

bool GetCooperateStateSyncParam::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadString(udId);
}

RegisterHotAreaListenerParam::RegisterHotAreaListenerParam(int32_t userData, bool checkPermission) : userData(userData),
    checkPermission(checkPermission)
{}

bool RegisterHotAreaListenerParam::Marshalling(MessageParcel &parcel) const
{
    return parcel.WriteInt32(userData) &&
        parcel.WriteBool(checkPermission);
}

bool RegisterHotAreaListenerParam::Unmarshalling(MessageParcel &parcel)
{
    return parcel.ReadInt32(userData) &&
        parcel.ReadBool(checkPermission);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
