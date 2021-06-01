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

#ifndef MULTIMODAL_INPUT_SERVICE_H
#define MULTIMODAL_INPUT_SERVICE_H

#include <mutex>
#include <thread>

#include "iremote_stub.h"
#include "system_ability.h"

#include "multimodal_input_service_stub.h"
#include "keyboard_inject.h"

namespace OHOS {
enum class ServiceRunningState {
    STATE_STOPPED,
    STATE_RUNNING
};

class MultimodalInputService : public SystemAbility, public MultimodalInputServiceStub {
DECLARE_SYSTEM_ABILITY(MultimodalInputService)

public:
    explicit MultimodalInputService(int32_t systemAbilityId, bool runOnCreate = false);
    virtual ~MultimodalInputService() = default;

    // SA function
    int32_t InjectEvent(const sptr<MultimodalEvent> &event) override;
    void ConnectHDFInit();
    // SA callback method
    void OnDump() override;
    void OnStart() override;
    void OnStop() override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId,
        const sptr<IRemoteObject>& ability) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
private:
    ServiceRunningState state_ { ServiceRunningState::STATE_STOPPED };
    std::mutex lock_;
    MMIS::InjectThread injectThread_;
    std::thread thread_;
};
} // namespace OHOS

#endif // MULTIMODAL_INPUT_SERVICE_H
