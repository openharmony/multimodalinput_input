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

#ifndef DSOFTBUS_ADAPTER_H
#define DSOFTBUS_ADAPTER_H

#include "nocopyable.h"

#include "i_dsoftbus_adapter.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DSoftbusAdapter final : public IDSoftbusAdapter {
public:
    DSoftbusAdapter() = default;
    ~DSoftbusAdapter() = default;
    DISALLOW_COPY_AND_MOVE(DSoftbusAdapter);

    int32_t Enable() override;
    void Disable() override;

    void AddObserver(std::shared_ptr<IDSoftbusObserver> observer) override;
    void RemoveObserver(std::shared_ptr<IDSoftbusObserver> observer) override;

    int32_t OpenSession(const std::string &networkId) override;
    void CloseSession(const std::string &networkId) override;
    void CloseAllSessions() override;

    int32_t SendPacket(const std::string &networkId, NetPacket &packet) override;
    int32_t SendParcel(const std::string &networkId, Parcel &parcel) override;
    int32_t BroadcastPacket(NetPacket &packet) override;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DSOFTBUS_ADAPTER_H
