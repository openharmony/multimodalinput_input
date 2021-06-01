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

#include "multimodal_input_service.h"

#include <list>

#include "key_event.h"
#include "mmi_log.h"
#include "multimodal_input_errors.h"
#include "system_ability_definition.h"

namespace OHOS {
REGISTER_SYSTEM_ABILITY_BY_ID(MultimodalInputService, MULTIMODAL_INPUT_SERVICE_ID, true);

MultimodalInputService::MultimodalInputService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
}

void MultimodalInputService::ConnectHDFInit()
{
    MMIS::KeyboardInject::GetInstance();
    thread_ = std::thread(&MMIS::InjectThread::InjectFunc, injectThread_);
}

int32_t MultimodalInputService::InjectEvent(const sptr<MultimodalEvent> &event)
{
    KeyEvent *eventPtr = reinterpret_cast<KeyEvent*>(event.GetRefPtr());
    int keycode = eventPtr->GetKeyCode();
    int state = 0;
    if (eventPtr->IsKeyDown()) {
        state = 1;
    } else {
        state = 0;
    }
    MMIS::KeyboardInject &inject = OHOS::MMIS::KeyboardInject::GetInstance();
    MMI_LOGD("InjectEvent keycode %{public}d, state %{public}d", keycode, state);
    inject.InjectKeyEvent(keycode, state);
    return 0;
}

void MultimodalInputService::OnDump()
{
}

void MultimodalInputService::OnStart()
{
    std::lock_guard<std::mutex> guard(lock_);
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        MMI_LOGE("Leave, FAILED, already running");
        return;
    }

    bool ret = SystemAbility::Publish(this);
    if (!ret) {
        MMI_LOGE("Leave, Failed to publish MultimodalInputService");
        return;
    }
    MMI_LOGD("Publish MultimodalInputService SUCCESS");

    state_ = ServiceRunningState::STATE_RUNNING;
    ConnectHDFInit();
    MMI_LOGD("Leave, SUCCESS");
}

void MultimodalInputService::OnStop()
{
    MMI_LOGD("Enter");
    std::lock_guard<std::mutex> guard(lock_);
    state_ = ServiceRunningState::STATE_STOPPED;
    MMI_LOGD("Leave, SUCCESS");
}

void MultimodalInputService::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId,
    const sptr<IRemoteObject>& ability)
{
}

void MultimodalInputService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
}

} // namespace OHOS
