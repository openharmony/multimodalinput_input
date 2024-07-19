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

#ifndef I_DINPUT_ADAPTER_H
#define I_DINPUT_ADAPTER_H

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IDInputAdapter {
public:
    struct BusinessEvent {
        int32_t keyCode;
        int32_t keyAction;
        std::vector<int32_t> pressedKeys;
    };

    using DInputCallback = std::function<void(bool)>;

    IDInputAdapter() = default;
    virtual ~IDInputAdapter() = default;

    virtual bool IsNeedFilterOut(const std::string &networkId, BusinessEvent &&event) = 0;

    virtual int32_t StartRemoteInput(const std::string &remoteNetworkId, const std::string &originNetworkId,
        const std::vector<std::string> &inputDeviceDhids, DInputCallback callback) = 0;
    virtual int32_t StopRemoteInput(const std::string &remoteNetworkId, const std::string &originNetworkId,
        const std::vector<std::string> &inputDeviceDhids, DInputCallback callback) = 0;

    virtual int32_t StopRemoteInput(const std::string &originNetworkId,
        const std::vector<std::string> &inputDeviceDhids, DInputCallback callback) = 0;

    virtual int32_t PrepareRemoteInput(const std::string &remoteNetworkId,
        const std::string &originNetworkId, DInputCallback callback) = 0;
    virtual int32_t UnPrepareRemoteInput(const std::string &remoteNetworkId,
        const std::string &originNetworkId, DInputCallback callback) = 0;

    virtual int32_t PrepareRemoteInput(const std::string &networkId, DInputCallback callback) = 0;
    virtual int32_t UnPrepareRemoteInput(const std::string &networkId, DInputCallback callback) = 0;
    virtual int32_t RegisterSessionStateCb(std::function<void(uint32_t)> callback) = 0;
    virtual int32_t UnregisterSessionStateCb() = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_DINPUT_ADAPTER_H
