/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "system_ability_definition.h"

#include "mmi_log.h"
#include "multimodal_input_connect_death_recipient.h"
#include "multimodal_input_connect_define.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
std::shared_ptr<MultimodalInputConnectManager> g_instance = nullptr;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MultimodalInputConnectManager"};
} // namespace

std::shared_ptr<MultimodalInputConnectManager> MultimodalInputConnectManager::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        g_instance.reset(new (std::nothrow) MultimodalInputConnectManager());
    });

    CHKPP(g_instance);
    if (g_instance != nullptr) {
        g_instance->ConnectMultimodalInputService();
    }
    return g_instance;
}

int32_t MultimodalInputConnectManager::AllocSocketPair(const int32_t moduleType)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_LOGE("client has not connect server");
        return RET_ERR;
    }

    const std::string programName(GetProgramName());
    int32_t result = multimodalInputConnectService_->AllocSocketFd(programName, moduleType, socketFd_);
    if (result != RET_OK) {
        MMI_LOGE("AllocSocketFd has error:%{public}d", result);
        return RET_ERR;
    }

    MMI_LOGI("AllocSocketPair success. socketFd_:%{public}d", socketFd_);
    return RET_OK;
}

int32_t MultimodalInputConnectManager::GetClientSocketFdOfAllocedSocketPair() const
{
    CALL_LOG_ENTER;
    return socketFd_;
}

int32_t MultimodalInputConnectManager::AddInputEventFilter(sptr<IEventFilter> filter)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_LOGE("multimodalInputConnectService_ is nullptr");
        return RET_ERR;
    }
    return multimodalInputConnectService_->AddInputEventFilter(filter);
}

bool MultimodalInputConnectManager::ConnectMultimodalInputService()
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ != nullptr) {
        return true;
    }
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sm == nullptr) {
        MMI_LOGE("get system ability manager fail");
        return false;
    }
    auto sa = sm->GetSystemAbility(IMultimodalInputConnect::MULTIMODAL_INPUT_CONNECT_SERVICE_ID);
    if (sa == nullptr) {
        MMI_LOGE("get sa fail");
        return false;
    }

    std::weak_ptr<MultimodalInputConnectManager> weakPtr = shared_from_this();
    auto deathCallback = [weakPtr](const wptr<IRemoteObject> &object) {
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr != nullptr) {
            sharedPtr->OnDeath();
        }
    };

    multimodalInputConnectRecipient_ = new (std::nothrow) MultimodalInputConnectDeathRecipient(deathCallback);
    CHKPF(multimodalInputConnectRecipient_);
    sa->AddDeathRecipient(multimodalInputConnectRecipient_);
    multimodalInputConnectService_ = iface_cast<IMultimodalInputConnect>(sa);
    if (multimodalInputConnectService_ == nullptr) {
        MMI_LOGE("get multimodalinput service fail");
        return false;
    }
    MMI_LOGI("get multimodalinput service successful");
    return true;
}

void MultimodalInputConnectManager::OnDeath()
{
    CALL_LOG_ENTER;
    Clean();
    NotifyDeath();
}

void MultimodalInputConnectManager::Clean()
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(lock_);
    if (multimodalInputConnectService_ != nullptr) {
        multimodalInputConnectService_.clear();
        multimodalInputConnectService_ = nullptr;
    }

    if (multimodalInputConnectRecipient_ != nullptr) {
        multimodalInputConnectRecipient_.clear();
        multimodalInputConnectRecipient_ = nullptr;
    }
}

void MultimodalInputConnectManager::NotifyDeath()
{
    CALL_LOG_ENTER;

    int32_t retryCount = 50;
    do {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (ConnectMultimodalInputService()) {
            MMI_LOGD("connect multimodalinput service successful");
            return;
        }
    } while (--retryCount > 0);
}
} // namespace MMI
} // namespace OHOS
