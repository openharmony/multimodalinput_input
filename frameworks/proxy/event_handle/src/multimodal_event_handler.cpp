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
#include "immi_token.h"
#include "input_event.h"
#include "mmi_client.h"
#include "proto.h"

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
#ifdef OHOS_WESTEN_MODEL
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
#else
    return RET_OK;
#endif
}

int32_t MultimodalEventHandler::UnregisterStandardizedEventHandle(const sptr<IRemoteObject> token,
    int32_t windowId, StandEventPtr standardizedEventHandle)
{
#ifdef OHOS_WESTEN_MODEL
    return EventManager.UnregisterStandardizedEventHandle(token, windowId, standardizedEventHandle);
#else
    return RET_OK;
#endif
}

int32_t MultimodalEventHandler::InjectEvent(const OHOS::KeyEvent& keyEvent)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    return EventManager.InjectEvent(keyEvent);
}

int32_t MultimodalEventHandler::InjectEvent(const OHOS::MMI::KeyEvent& keyEvent)
{
    if (!InitClient()) {
      return MMI_SERVICE_INVALID;
    }
    return EventManager.InjectEvent(keyEvent);
}

int32_t MultimodalEventHandler::InjectEvent(const std::shared_ptr<OHOS::MMI::KeyEvent> keyEventPtr)
{
    if (!InitClient()) {
      return MMI_SERVICE_INVALID;
    }
    return EventManager.InjectEvent(keyEventPtr);
}

int32_t MultimodalEventHandler::GetMultimodeInputInfo()
{
    if (!InitClient()) {
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

MMIClientPtr MultimodalEventHandler::GetMMIClient()
{
    if (InitClient()) {
        return mClient_;
    }
    return nullptr;
}

int32_t MultimodalEventHandler::GetDeviceIds(int32_t taskId)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    return EventManager.GetDeviceIds(taskId);
}

int32_t MultimodalEventHandler::GetDevice(int32_t taskId, int32_t deviceId)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    return EventManager.GetDevice(taskId, deviceId);
}

int32_t MultimodalEventHandler::InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    return EventManager.InjectPointerEvent(pointerEvent);
}

int32_t MultimodalEventHandler::AddKeyEventFIlter(int32_t id, std::string name, Authority authority)
{
    if (authority < NO_AUTHORITY || authority > HIGH_AUTHORITY) {
        MMI_LOGD("the input authority is incorrect");
        return RET_ERR;
    }
    OHOS::MMI::NetPacket ckt(MmiMessageId::ADD_KEY_EVENT_INTERCEPTOR);
    MMI_LOGD("client add a key event filter");
    ckt<<id<<name<<authority;
    mClient_->SendMessage(ckt);
    return RET_OK;
}

int32_t MultimodalEventHandler::RemoveKeyEventFIlter(int32_t id)
{
    OHOS::MMI::NetPacket ckt(MmiMessageId::REMOVE_KEY_EVENT_INTERCEPTOR);
    MMI_LOGD("client remove a key event filter");
    ckt<<id;
    mClient_->SendMessage(ckt);
    return RET_OK;
}

int32_t MultimodalEventHandler::AddTouchEventFilter(int32_t id, std::string name, Authority authority)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    MMI_LOGD("client add a touch event filter");
    OHOS::MMI::NetPacket ckt(MmiMessageId::ADD_TOUCH_EVENT_INTERCEPTOR);
    int32_t ret = OHOS::MMI_STANDARD_EVENT_SUCCESS;
    ckt << id << name << authority;
    mClient_->SendMessage(ckt);
    return ret;
}

int32_t MultimodalEventHandler::RemoveTouchEventFilter(int32_t id)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    MMI_LOGD("client remove a touch event filter");
    OHOS::MMI::NetPacket ckt(MmiMessageId::REMOVE_TOUCH_EVENT_INTERCEPTOR);
    int32_t ret = OHOS::MMI_STANDARD_EVENT_SUCCESS;
    ckt << id;
    mClient_->SendMessage(ckt);
    return ret;
}

int32_t MultimodalEventHandler::AddEventInterceptor(int32_t id, std::string name, Authority authority)
{
    if (authority < NO_AUTHORITY || authority > HIGH_AUTHORITY) {
        MMI_LOGD("the input authority is incorrect");
        return RET_ERR;
    }
    OHOS::MMI::NetPacket ckt(MmiMessageId::ADD_POINTER_INTERCEPTOR);
    MMI_LOGD("client add a pointer event interceptor");
    ckt << id << name << authority;
    mClient_->SendMessage(ckt);
    return RET_OK;
}

int32_t MultimodalEventHandler::RemoveEventInterceptor(int32_t id)
{
    OHOS::MMI::NetPacket ckt(MmiMessageId::REMOVE_POINTER_INTERCEPTOR);
    MMI_LOGD("client remove a pointer event interceptor");
    ckt << id;
    mClient_->SendMessage(ckt);
    return RET_OK;
}

int32_t MultimodalEventHandler::AddInterceptor(int32_t sourceType, int32_t id)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }

    OHOS::MMI::NetPacket ck(MmiMessageId::ADD_EVENT_INTERCEPTOR);
    ck << sourceType << id;
    mClient_->SendMessage(ck);
    MMI_LOGD("client add a touchpad event interceptor");
    return RET_OK;
}


int32_t MultimodalEventHandler::RemoveInterceptor(int32_t id)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }

    OHOS::MMI::NetPacket ckt(MmiMessageId::REMOVE_EVENT_INTERCEPTOR);
    ckt << id;
    mClient_->SendMessage(ckt);
    MMI_LOGD("client remove a touchpad event interceptor");
    return RET_OK;
}

int32_t MultimodalEventHandler::AddInputEventMontior(int32_t keyEventType)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    NetPacket ck(MmiMessageId::ADD_INPUT_EVENT_MONITOR);
    ck << OHOS::MMI::InputEvent::EVENT_TYPE_KEY;
    mClient_->SendMessage(ck);
    return RET_OK;
}

void MultimodalEventHandler::RemoveInputEventMontior(int32_t keyEventType)
{
    if (!InitClient()) {
        return;
    }
    NetPacket ck(MmiMessageId::REMOVE_INPUT_EVENT_MONITOR);
    ck << OHOS::MMI::InputEvent::EVENT_TYPE_KEY;
    mClient_->SendMessage(ck);
}

void MultimodalEventHandler::RemoveInputEventTouchpadMontior(int32_t pointerEventType)
{
    MMI_LOGD("MultimodalEventHandler::RemoveInputEventTouchpadMontior");
    if (!InitClient()) {
        return;
    }
    NetPacket ck(MmiMessageId::REMOVE_INPUT_EVENT_TOUCHPAD_MONITOR);
    ck << OHOS::MMI::InputEvent::EVENT_TYPE_POINTER;
    mClient_->SendMessage(ck);
}

int32_t MultimodalEventHandler::AddInputEventTouchpadMontior(int32_t pointerEventType)
{
    MMI_LOGE("MultimodalEventHandler::AddInputEventTouchpadMontior");
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    NetPacket ck(MmiMessageId::ADD_INPUT_EVENT_TOUCHPAD_MONITOR);
    ck << OHOS::MMI::InputEvent::EVENT_TYPE_POINTER;
    MMI_LOGE("send msg before");
    bool isSuc = mClient_->SendMessage(ck);
    if (isSuc)
        MMI_LOGD("sendAdd msg Success");
    return RET_OK;
}
}
}
