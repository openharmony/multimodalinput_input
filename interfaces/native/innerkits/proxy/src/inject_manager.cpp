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

#include "inject_manager.h"

#include <chrono>
#include <thread>

#include "iservice_registry.h"
#include "mmi_log.h"
#include "multimodal_death_recipient.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace {
    std::shared_ptr<InjectManager> g_instance;
    constexpr uint32_t CONNECT_SERVICE_WAIT_TIME = 1000; // ms
    constexpr uint32_t CONNECT_MAX_TRY_COUNT = 50;
}

std::shared_ptr<InjectManager> InjectManager::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        g_instance.reset(new InjectManager());
        g_instance->ConnectMultimodalInputService();
    });
    return g_instance;
}

bool InjectManager::InjectEvent(const sptr<MultimodalEvent> event)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (!multimodalInputService_) {
        return false;
    }

    int32_t result = multimodalInputService_->InjectEvent(event);
    if (result == 0) {
        return true;
    }

    MMI_LOGI("inject failed");
    return false;
}

bool InjectManager::ConnectMultimodalInputService()
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputService_) {
        return true;
    }
    sptr<ISystemAbilityManager> sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!sm) {
        MMI_LOGE("get registry fail");
        return false;
    }
    auto sa = sm->GetSystemAbility(MULTIMODAL_INPUT_SERVICE_ID);
    if (!sa) {
        MMI_LOGE("get sa fail");
        return false;
    }

    std::weak_ptr<InjectManager> weakPtr = shared_from_this();
    auto deathCallback = [weakPtr](const wptr<IRemoteObject> &object) {
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr) {
            sharedPtr->OnDeath();
        }
    };

    multimodalRecipient_ = new MultimodalDeathRecipient(deathCallback);
    sa->AddDeathRecipient(multimodalRecipient_);
    multimodalInputService_ = iface_cast<IMultimodalInputService>(sa);
    if (!multimodalInputService_) {
        MMI_LOGE("get service is null");
        return false;
    }
    MMI_LOGI("get multimodal input service successful");
    return true;
}

void InjectManager::OnDeath()
{
    Clean();
    NotifyDeath();
}

void InjectManager::Clean()
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputService_) {
        multimodalInputService_.clear();
        multimodalInputService_ = nullptr;
    }

    if (multimodalRecipient_) {
        multimodalRecipient_.clear();
        multimodalRecipient_ = nullptr;
    }
}

void InjectManager::NotifyDeath()
{
    MMI_LOGD("service is dead, connect again");
    for (uint32_t i = 0; i < CONNECT_MAX_TRY_COUNT; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(CONNECT_SERVICE_WAIT_TIME));
        bool result = ConnectMultimodalInputService();
        if (result) {
            MMI_LOGD("connect multimodal input service successful");
            return;
        }
    }
    MMI_LOGI("connect multimodal input service failed");
}
} // namespace OHOS
