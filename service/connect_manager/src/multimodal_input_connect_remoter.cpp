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

#include "multimodal_input_connect_remoter.h"

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
std::shared_ptr<MultimodalInputConnectRemoter> g_instance = nullptr;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MultimodalInputConnectRemoter"};
} // namespace

std::shared_ptr<MultimodalInputConnectRemoter> MultimodalInputConnectRemoter::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        g_instance.reset(new (std::nothrow) MultimodalInputConnectRemoter());
    });
    return g_instance;
}

int32_t MultimodalInputConnectRemoter::StartRemoteCooperate(const std::string &localDeviceId,
    const std::string &remoteDeviceId)
{
    CALL_DEBUG_ENTER;
    auto proxy = GetProxyById(remoteDeviceId);
    CHKPR(proxy, RET_ERR);
    return proxy->StartRemoteCooperate(localDeviceId);
}

int32_t MultimodalInputConnectRemoter::StartRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess,
    const std::string &startDhid, int32_t xPercent, int32_t yPercent)
{
    CALL_DEBUG_ENTER;
    auto proxy = GetProxyById(remoteDeviceId);
    CHKPR(proxy, RET_ERR);
    return proxy->StartRemoteCooperateResult(isSuccess, startDhid, xPercent, yPercent);
}

int32_t MultimodalInputConnectRemoter::StopRemoteCooperate(const std::string &remoteDeviceId)
{
    CALL_DEBUG_ENTER;
    auto proxy = GetProxyById(remoteDeviceId);
    CHKPR(proxy, RET_ERR);
    return proxy->StopRemoteCooperate();
}

int32_t MultimodalInputConnectRemoter::StopRemoteCooperateResult(const std::string &remoteDeviceId, bool isSuccess)
{
    CALL_DEBUG_ENTER;
    auto proxy = GetProxyById(remoteDeviceId);
    CHKPR(proxy, RET_ERR);
    return proxy->StopRemoteCooperateResult(isSuccess);
}

int32_t MultimodalInputConnectRemoter::StartCooperateOtherResult(const std::string &remoteDeviceId,
    const std::string &srcNetworkId)
{
    CALL_DEBUG_ENTER;
    auto proxy = GetProxyById(remoteDeviceId);
    CHKPR(proxy, RET_ERR);
    return proxy->StartCooperateOtherResult(srcNetworkId);
}

sptr<IMultimodalInputConnect> MultimodalInputConnectRemoter::GetProxyById(const std::string &remoteDeviceId)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(lock_);
    auto iterService = mmiRemoteServices_.find(remoteDeviceId);
    if (iterService != mmiRemoteServices_.end()) {
        return iterService->second;
    }
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHKPP(sm);
    auto sa = sm->GetSystemAbility(IMultimodalInputConnect::MULTIMODAL_INPUT_CONNECT_SERVICE_ID, remoteDeviceId);
    CHKPP(sa);
    std::weak_ptr<MultimodalInputConnectRemoter> weakPtr = shared_from_this();
    auto deathCallback = [remoteDeviceId, weakPtr](const wptr<IRemoteObject> &object) {
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr != nullptr) {
            sharedPtr->OnRemoteDeath(remoteDeviceId);
        }
    };
    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new (std::nothrow) MultimodalInputConnectDeathRecipient(deathCallback);
    CHKPP(deathRecipient);
    sa->AddDeathRecipient(deathRecipient);
    auto retDeath = mmiDeathRecipients_.emplace(remoteDeviceId, deathRecipient);
    if (!retDeath.second) {
        MMI_HILOGE("Get proxy faild, death recipient not set");
        return nullptr;
    }
    sptr<IMultimodalInputConnect> remoteService = iface_cast<IMultimodalInputConnect>(sa);
    if (remoteService == nullptr) {
        MMI_HILOGE("Get proxy faild, get remote service is null!");
        OnRemoteDeath(remoteDeviceId);
        return nullptr;
    }
    auto retService = mmiRemoteServices_.emplace(remoteDeviceId, remoteService);
    if (!retService.second) {
        MMI_HILOGE("Get proxy faild, remote service not set!");
        OnRemoteDeath(remoteDeviceId);
        return nullptr;
    }
    return remoteService;
}

void MultimodalInputConnectRemoter::OnRemoteDeath(const std::string &remoteDeviceId)
{
    CALL_DEBUG_ENTER;
    auto iterService = mmiRemoteServices_.find(remoteDeviceId);
    if (iterService != mmiRemoteServices_.end()) {
        mmiRemoteServices_.erase(iterService);
    }
    auto iterRecipient = mmiDeathRecipients_.find(remoteDeviceId);
    if (iterRecipient != mmiDeathRecipients_.end()) {
        mmiDeathRecipients_.erase(iterRecipient);
    }
}
} // namespace MMI
} // namespace OHOS