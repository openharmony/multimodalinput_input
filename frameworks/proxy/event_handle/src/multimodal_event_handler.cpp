/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "multimodal_event_handler.h"
#include "mmi_client.h"
#include "proto.h"
#include "immi_token.h"

namespace OHOS {
namespace MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MultimodalEventHandler"};
    }

void OnConnected(const OHOS::MMI::IfMMIClient& client)
{
    int32_t winId = 0;
    int32_t abilityId = 0;
    std::string bundlerName = "EmptyBundlerName";
    std::string appName = "EmptyAppName";
    auto abilityInfoVec = MMIEventHdl.GetAbilityInfoVec();
    if (!abilityInfoVec.empty()) {
        winId = abilityInfoVec[0].windowId;
        abilityId = *reinterpret_cast<int32_t*>(abilityInfoVec[0].token.GetRefPtr());
        /* 三方联调代码，token中带bundlerName和appName，本注释三方代码修改后打开
        auto token = static_cast<IMMIToken*>(abilityInfoVec[0].token.GetRefPtr());
        if (token) {
            bundlerName = token->GetBundlerName();
            appName = token->GetName();
        }
        */
    }
    OHOS::MMI::NetPacket ckt(MmiMessageId::REGISTER_APP_INFO);
    ckt << abilityId << winId << bundlerName << appName;
    client.SendMessage(ckt);

    for (auto& val : abilityInfoVec) {
        if (val.sync == REG_STATUS_SYNCED) {
            val.sync = REG_STATUS_NOT_SYNC;
            continue;
        }
        EventManager.RegisterStandardizedEventHandle(val.token, val.windowId, val.standardizedEventHandle);
    }
}

MultimodalEventHandler::MultimodalEventHandler()
{
#ifdef OHOS_BUILD_MMI_DEBUG
    VerifyLogManagerRun();
#endif
}

int32_t MultimodalEventHandler::RegisterStandardizedEventHandle(const sptr<IRemoteObject> token,
    int32_t windowId, StandEventPtr standardizedEventHandle)
{
    KMSG_LOGI("Register Standardized Event Handle start!");
    MMI_LOGT("Register Standardized Event Handle start!");
    int32_t ret = OHOS::MMI_STANDARD_EVENT_SUCCESS;
    EventRegesterInfo regInfo = {};
    if (mClient_ && mClient_->GetCurrentConnectedStatus()) {
        regInfo.sync = REG_STATUS_SYNCED;
        ret = EventManager.RegisterStandardizedEventHandle(token, windowId, standardizedEventHandle);
    }
    regInfo.token = token;
    regInfo.windowId = windowId;
    regInfo.standardizedEventHandle = standardizedEventHandle;
    mAbilityInfoVec_.push_back(regInfo);

    if (!InitClient()) {
        MMI_LOGE("init client failed!");
        return OHOS::MMI_STANDARD_EVENT_INVALID_PARAMETER;
    }
    MMI_LOGT("Register Standardized Event Handle end!");
    return ret;
}

int32_t MultimodalEventHandler::UnregisterStandardizedEventHandle(const sptr<IRemoteObject> token,
    int32_t windowId, StandEventPtr standardizedEventHandle)
{
    return EventManager.UnregisterStandardizedEventHandle(token, windowId, standardizedEventHandle);
}

int32_t MultimodalEventHandler::InjectEvent(const KeyEvent& keyEvent)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    return EventManager.InjectEvent(keyEvent);
}

int32_t MultimodalEventHandler::GetMultimodeInputInfo()
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    if (!mClient_->GetCurrentConnectedStatus()) {
        return MMI_SERVICE_INVALID;
    }
    return MMI_SERVICE_RUNNING;
}

std::vector<EventRegesterInfo>& MultimodalEventHandler::GetAbilityInfoVec()
{
    return mAbilityInfoVec_;
}

bool MultimodalEventHandler::InitClient()
{
    MMI_LOGT("enter");
    if (mClient_) {
        return true;
    }
    mClient_ = std::make_shared<MMIClient>();
    CHKF(mClient_, OHOS::NULL_POINTER);
    mcMsgHandler_ = std::make_shared<ClientMsgHandler>();
    EventManager.SetClientHandle(mClient_);
    mClient_->RegisterConnectedFunction(&OnConnected);
    if (!(mClient_->Start(mcMsgHandler_, true))) {
        return false;
    }
    MMI_LOGT("init client success!");
    return true;
}
}
}
