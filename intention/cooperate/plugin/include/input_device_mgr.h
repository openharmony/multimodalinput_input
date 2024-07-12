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

#ifndef COOPERATE_INPUT_DEVICE_MANAGER_H
#define COOPERATE_INPUT_DEVICE_MANAGER_H

#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>

#include "nocopyable.h"

#include "channel.h"
#include "cooperate_events.h"
#include "i_context.h"
#include "net_packet.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class InputDeviceMgr {
public:
    InputDeviceMgr(IContext *context);
    ~InputDeviceMgr() = default;
    DISALLOW_COPY_AND_MOVE(InputDeviceMgr);

public:
    void Enable();
    void Disable();
    void OnSoftbusSessionOpened(const DSoftbusSessionOpened &notice);
    void OnSoftbusSessionClosed(const DSoftbusSessionClosed &notice);
    void OnLocalHotPlug(const InputHotplugEvent &notice);
    void AddVirtualInputDevice(const std::string &networkId);
    void RemoveVirtualInputDevice(const std::string &networkId);
    void HandleRemoteHotPlug(const DSoftbusHotPlugEvent &notice);
    void OnRemoteInputDevice(const DSoftbusSyncInputDevice &notice);
    void OnRemoteHotPlug(const DSoftbusHotPlugEvent &notice);

private:
    void NotifyInputDeviceToRemote(const std::string &remoteNetworkId);
    void BroadcastHotPlugToRemote(const InputHotplugEvent &notice);
    void AddRemoteInputDevice(const std::string &networkId, std::shared_ptr<IDevice> device);
    void RemoveRemoteInputDevice(const std::string &networkId, std::shared_ptr<IDevice> device);
    void RemoveAllRemoteInputDevice(const std::string &networkId);
    void DumpRemoteInputDevice(const std::string &networkId);
    int32_t SerializeDevice(std::shared_ptr<IDevice> device, NetPacket &packet);
    std::shared_ptr<MMI::InputDevice> Transform(std::shared_ptr<IDevice> device);
    void AddVirtualInputDevice(const std::string &networkId, int32_t remoteDeviceId);
    void RemoveVirtualInputDevice(const std::string &networkId, int32_t remoteDeviceId);
    void DispDeviceInfo(std::shared_ptr<IDevice> device);
    std::shared_ptr<IDevice> GetRemoteDeviceById(const std::string &networkId, int32_t remoteDeviceId);

private:
    bool enable_ { false };
    IContext *env_ { nullptr };
    struct IDeviceCmp {
        bool operator()(const std::shared_ptr<IDevice> &one, const std::shared_ptr<IDevice> &other) const
        {
            return one->GetId() < other->GetId();
        }
    };
    std::unordered_map<std::string, std::set<std::shared_ptr<IDevice>, IDeviceCmp>> remoteDevices_;
    std::unordered_map<std::string, std::set<int32_t>> virtualInputDevicesAdded_;
    std::unordered_map<int32_t, int32_t> remote2VirtualIds_;
};

} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_INPUT_DEVICE_MANAGER_H
