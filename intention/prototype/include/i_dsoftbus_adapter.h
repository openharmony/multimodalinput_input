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

#ifndef I_DSOFTBUS_ADAPTER_H
#define I_DSOFTBUS_ADAPTER_H

#include <memory>
#include <string>

#include "net_packet.h"
#include "parcel.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IDSoftbusObserver {
public:
    IDSoftbusObserver() = default;
    virtual ~IDSoftbusObserver() = default;

    virtual void OnBind(const std::string &networkId) = 0;
    virtual void OnShutdown(const std::string &networkId) = 0;
    virtual void OnConnected(const std::string &networkId) = 0;
    virtual bool OnPacket(const std::string &networkId, NetPacket &packet) = 0;
    virtual bool OnRawData(const std::string &networkId, const void *data, uint32_t dataLen) = 0;
};

class IDSoftbusAdapter {
public:
    IDSoftbusAdapter() = default;
    virtual ~IDSoftbusAdapter() = default;

    virtual int32_t Enable() = 0;
    virtual void Disable() = 0;

    virtual void AddObserver(std::shared_ptr<IDSoftbusObserver> observer) = 0;
    virtual void RemoveObserver(std::shared_ptr<IDSoftbusObserver> observer) = 0;

    virtual int32_t OpenSession(const std::string &networkId) = 0;
    virtual void CloseSession(const std::string &networkId) = 0;
    virtual void CloseAllSessions() = 0;

    virtual int32_t SendPacket(const std::string &networkId, NetPacket &packet) = 0;
    virtual int32_t SendParcel(const std::string &networkId, Parcel &parcel) = 0;
    virtual int32_t BroadcastPacket(NetPacket &packet) = 0;

    static std::string GetLocalNetworkId();
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_DSOFTBUS_ADAPTER_H
