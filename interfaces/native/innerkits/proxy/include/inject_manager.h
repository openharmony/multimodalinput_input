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

#ifndef INPUT_MANAGER_H
#define INPUT_MANAGER_H

#include <memory>
#include <map>
#include <set>
#include <string>

#include "i_multimodal_input_service.h"

namespace OHOS {
class InjectManager : public std::enable_shared_from_this<InjectManager> {
public:
    virtual ~InjectManager() = default;
    static std::shared_ptr<InjectManager> GetInstance();
    bool InjectEvent(const sptr<MultimodalEvent> event);

private:
    InjectManager() = default;
    InjectManager(const InjectManager &manager) = delete;
    InjectManager& operator=(const InjectManager &manager) = delete;
    InjectManager(const InjectManager &&manager) = delete;
    InjectManager& operator=(const InjectManager &&manager) = delete;

    bool ConnectMultimodalInputService();
    void OnDeath();
    void Clean();
    void NotifyDeath();
    sptr<IMultimodalInputService> multimodalInputService_{nullptr};
    sptr<IRemoteObject::DeathRecipient> multimodalRecipient_{nullptr};
    std::mutex lock_;
};
} // namespace OHOS

#endif // INPUT_MANAGER_H
