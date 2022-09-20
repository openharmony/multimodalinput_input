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

#ifndef MULTIMODAL_INPUT_CONNECT_REMOTER_H
#define MULTIMODAL_INPUT_CONNECT_REMOTER_H

#include <map>
#include <memory>
#include <string>

#include "nocopyable.h"

#include "i_multimodal_input_connect.h"

namespace OHOS {
namespace MMI {
class MultimodalInputConnectRemoter : public std::enable_shared_from_this<MultimodalInputConnectRemoter> {
public:
    virtual ~MultimodalInputConnectRemoter() = default;
    static std::shared_ptr<MultimodalInputConnectRemoter> GetInstance();
    int32_t StartRemoteCooperate(const std::string &localDeviceId, const std::string &remoteDeviceId);
    int32_t StartRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess,
        const std::string &startDhid, int32_t xPercent, int32_t yPercent);
    int32_t StopRemoteCooperate(const std::string &remoteDeviceId);
    int32_t StopRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess);
    int32_t StartCooperateOtherResult(const std::string &remoteDeviceId, const std::string &srcNetworkId);

private:
    MultimodalInputConnectRemoter() = default;
    DISALLOW_COPY_AND_MOVE(MultimodalInputConnectRemoter);

    sptr<IMultimodalInputConnect> GetProxyById(const std::string &remoteDeviceId);
    void OnRemoteDeath(const std::string &remoteDeviceId);
    std::mutex lock_;
    std::map<std::string, sptr<IMultimodalInputConnect>> mmiRemoteServices_;
    std::map<std::string, sptr<IRemoteObject::DeathRecipient>> mmiDeathRecipients_;
};
} // namespace MMI
} // namespace OHOS
#define RemoteMgr MultimodalInputConnectRemoter::GetInstance()
#endif // MULTIMODAL_INPUT_CONNECT_REMOTER_H
