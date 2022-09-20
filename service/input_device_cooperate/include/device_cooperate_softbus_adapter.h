/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef INPUT_DEVICE_COOPERATE_ADAPTER_H
#define INPUT_DEVICE_COOPERATE_ADAPTER_H

#include <map>
#include <memory>
#include <string>

#include "nlohmann/json.hpp"
#include "nocopyable.h"
#include "session.h"

#include "i_multimodal_input_connect.h"

namespace OHOS {
namespace MMI {
class DeviceCooperateSoftbusAdapter {
public:
    virtual ~DeviceCooperateSoftbusAdapter() = default;
    static std::shared_ptr<DeviceCooperateSoftbusAdapter> GetInstance();
    int32_t StartRemoteCooperate(const std::string &localDeviceId, const std::string &remoteDeviceId);
    int32_t StartRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess,
        const std::string &startDhid, int32_t xPercent, int32_t yPercent);
    int32_t StopRemoteCooperate(const std::string &remoteDeviceId);
    int32_t StopRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess);
    int32_t StartCooperateOtherResult(const std::string &remoteDeviceId, const std::string &srcNetworkId);

    int32_t Init();
    void Release();
    int32_t OpenInputSoftbus(const std::string &remoteDevId);
    void CloseInputSoftbus(const std::string &remoteDevId);

    int32_t OnSessionOpened(int32_t sessionId, int32_t result);
    void OnSessionClosed(int32_t sessionId);
    void OnBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen);

private:
    DeviceCooperateSoftbusAdapter() = default;
    DISALLOW_COPY_AND_MOVE(DeviceCooperateSoftbusAdapter);
    std::string FindDeviceBySession(int32_t sessionId);
    int32_t SendMsg(int32_t sessionId, std::string &message);
    int32_t CheckDeviceSessionState(const std::string &remoteDevId);
    void HandleSessionData(int32_t sessionId, const std::string& messageData);

    void NotifyResponseStartRemoteCooperate(int32_t sessionId, const nlohmann::json &recMsg);
    void NotifyResponseStartRemoteCooperateResult(int32_t sessionId, const nlohmann::json &recMsg);
    void NotifyResponseStopRemoteCooperate(int32_t sessionId, const nlohmann::json &recMsg);
    void NotifyResponseStopRemoteCooperateResult(int32_t sessionId, const nlohmann::json &recMsg);
    void NotifyResponseStartCooperateOtherResult(int32_t sessionId, const nlohmann::json &recMsg);

    std::map<std::string, int32_t> sessionDevMap_;
    std::map<std::string, bool> channelStatusMap_;
    std::mutex operationMutex_;
    std::string mySessionName_ = "";
    std::condition_variable openSessionWaitCond_;
    ISessionListener sessListener_;
};
} // namespace MMI
} // namespace OHOS
#define DevCooperateSoftbusAdapter DeviceCooperateSoftbusAdapter::GetInstance()
#endif // INPUT_DEVICE_COOPERATE_ADAPTER_H
