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

#include "multimodal_input_connect_manager.h"
#include <chrono>
#include <thread>
#include "iservice_registry.h"
#include "log.h"
#include "multimodal_input_connect_death_recipient.h"
#include "multimodal_input_connect_define.h"
#include "system_ability_definition.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
    std::shared_ptr<MultimodalInputConnectManager> g_instance;
    constexpr uint32_t CONNECT_SERVICE_WAIT_TIME = 1000; // ms
    constexpr uint32_t CONNECT_MAX_TRY_COUNT = 50;
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MultimodalInputConnectManager" };
}

std::shared_ptr<MultimodalInputConnectManager> MultimodalInputConnectManager::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        g_instance.reset(new MultimodalInputConnectManager());
        g_instance->ConnectMultimodalInputService();
    });
    return g_instance;
}

int32_t MultimodalInputConnectManager::AllocSocketPair(const int moduleType)
{
    MMI_LOGT("enter.");
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_LOGE("client has not connect server.");
        return RET_ERR;
    }

    const std::string programName(OHOS::MMI::GetProgramName());
    int32_t result = multimodalInputConnectService_->AllocSocketFd(programName, moduleType, socketFd_);
    if (result != RET_OK) {
        MMI_LOGE("AllocSocketFd has error: %{public}d.", result);
        return RET_ERR;
    }

    MMI_LOGI("AllocSocketPair success. socketFd_ = %{public}d.", socketFd_);

    return RET_OK;
}

int MultimodalInputConnectManager::GetClientSocketFdOfAllocedSocketPair() const
{
    MMI_LOGT("enter");
    return socketFd_;
}

bool MultimodalInputConnectManager::ConnectMultimodalInputService()
{
    MMI_LOGT("enter");
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ != nullptr) {
        return true;
    }
    sptr<ISystemAbilityManager> sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!sm) {
        MMI_LOGE("get registry fail.");
        return false;
    }
    auto sa = sm->GetSystemAbility(IMultimodalInputConnect::MULTIMODAL_INPUT_CONNECT_SERVICE_ID);
    if (!sa) {
        MMI_LOGE("get sa fail.");
        return false;
    }

    std::weak_ptr<MultimodalInputConnectManager> weakPtr = shared_from_this();
    auto deathCallback = [weakPtr](const wptr<IRemoteObject> &object) {
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr) {
            sharedPtr->OnDeath();
        }
    };

    multimodalInputConnectRecipient_ = new MultimodalInputConnectDeathRecipient(deathCallback);
    sa->AddDeathRecipient(multimodalInputConnectRecipient_);
    multimodalInputConnectService_ = iface_cast<IMultimodalInputConnect>(sa);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_LOGE("get multimodal input connect service fail.");
        return false;
    }
    MMI_LOGI("get multimodal input connect service successful.");
    return true;
}

void MultimodalInputConnectManager::OnDeath()
{
    MMI_LOGT("enter");
    Clean();
    NotifyDeath();
}

void MultimodalInputConnectManager::Clean()
{
    MMI_LOGT("enter");
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_) {
        multimodalInputConnectService_.clear();
        multimodalInputConnectService_ = nullptr;
    }

    if (multimodalInputConnectRecipient_) {
        multimodalInputConnectRecipient_.clear();
        multimodalInputConnectRecipient_ = nullptr;
    }
}

void MultimodalInputConnectManager::NotifyDeath()
{
    MMI_LOGT("multimodal input connect service is dead, connect again");
    for (uint32_t i = 0; i < CONNECT_MAX_TRY_COUNT; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(CONNECT_SERVICE_WAIT_TIME));
        bool result = ConnectMultimodalInputService();
        if (result) {
            MMI_LOGD("connect multimodal input connect service successful");
            return;
        }
    }
    MMI_LOGI("connectmultimodal input connect service failed");
}
} // namespace MMI
} // namespace OHOS
