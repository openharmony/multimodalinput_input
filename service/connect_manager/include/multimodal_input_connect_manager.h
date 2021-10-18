/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_MULTIMODAL_INPUT_CONNECT_MANAGER_H
#define OHOS_MULTIMODAL_INPUT_CONNECT_MANAGER_H

#include <memory>
#include <map>
#include <set>
#include <string>

#include "i_multimodal_input_connect.h"

namespace OHOS {
namespace MMI {
class MultimodalInputConnectManager : public std::enable_shared_from_this<MultimodalInputConnectManager> {
public:
    virtual ~MultimodalInputConnectManager() = default;
    static std::shared_ptr<MultimodalInputConnectManager> GetInstance();
    int32_t AllocSocketPair(const int moduleType);
    int GetClientSocketFdOfAllocedSocketPair() const;
private:
    MultimodalInputConnectManager() = default;
    MultimodalInputConnectManager(const MultimodalInputConnectManager &manager) = delete;
    MultimodalInputConnectManager& operator=(const MultimodalInputConnectManager &manager) = delete;
    MultimodalInputConnectManager(const MultimodalInputConnectManager &&manager) = delete;
    MultimodalInputConnectManager& operator=(const MultimodalInputConnectManager &&manager) = delete;

    bool ConnectMultimodalInputService();
    void OnDeath();
    void Clean();
    void NotifyDeath();
    sptr<IMultimodalInputConnect> multimodalInputConnectService_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> multimodalInputConnectRecipient_ = nullptr;
    std::mutex lock_;
    int socketFd_ = IMultimodalInputConnect::INVALID_SOCKET_FD;
};
} // namespace MMI
} // namespace OHOS

#endif // OHOS_MULTIMODAL_INPUT_CONNECT_MANAGER_H
