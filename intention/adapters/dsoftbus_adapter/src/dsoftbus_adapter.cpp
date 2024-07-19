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

#include "dsoftbus_adapter.h"

#include "dsoftbus_adapter_impl.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
int32_t DSoftbusAdapter::Enable()
{
    return DSoftbusAdapterImpl::GetInstance()->Enable();
}

void DSoftbusAdapter::Disable()
{
    DSoftbusAdapterImpl::GetInstance()->Disable();
}

void DSoftbusAdapter::AddObserver(std::shared_ptr<IDSoftbusObserver> observer)
{
    DSoftbusAdapterImpl::GetInstance()->AddObserver(observer);
}

void DSoftbusAdapter::RemoveObserver(std::shared_ptr<IDSoftbusObserver> observer)
{
    DSoftbusAdapterImpl::GetInstance()->RemoveObserver(observer);
}

int32_t DSoftbusAdapter::OpenSession(const std::string &networkId)
{
    return DSoftbusAdapterImpl::GetInstance()->OpenSession(networkId);
}

void DSoftbusAdapter::CloseSession(const std::string &networkId)
{
    DSoftbusAdapterImpl::GetInstance()->CloseSession(networkId);
}

void DSoftbusAdapter::CloseAllSessions()
{
    DSoftbusAdapterImpl::GetInstance()->CloseAllSessions();
}

int32_t DSoftbusAdapter::SendPacket(const std::string &networkId, NetPacket &packet)
{
    return DSoftbusAdapterImpl::GetInstance()->SendPacket(networkId, packet);
}

int32_t DSoftbusAdapter::SendParcel(const std::string &networkId, Parcel &parcel)
{
    return DSoftbusAdapterImpl::GetInstance()->SendParcel(networkId, parcel);
}

int32_t DSoftbusAdapter::BroadcastPacket(NetPacket &packet)
{
    return DSoftbusAdapterImpl::GetInstance()->BroadcastPacket(packet);
}

} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
