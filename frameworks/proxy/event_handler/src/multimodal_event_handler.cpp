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

#include "multimodal_event_handler.h"

#include "proto.h"

#include "input_event.h"
#include "input_manager_impl.h"
#include "input_handler_manager.h"
#include "mmi_client.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MultimodalEventHandler"};
} // namespace

void OnConnected(const IfMMIClient& client)
{
    CALL_LOG_ENTER;
    InputMgrImpl->OnConnected();
    KeyEventInputSubscribeMgr.OnConnected();
    InputHandlerManager::GetInstance().OnConnected();
}

MultimodalEventHandler::MultimodalEventHandler() {}

int32_t MultimodalEventHandler::InjectEvent(const std::shared_ptr<KeyEvent> keyEventPtr)
{
    CHKPR(keyEventPtr, ERROR_NULL_POINTER);
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }
    return EventManager.InjectEvent(keyEventPtr);
}

bool MultimodalEventHandler::StartClient()
{
    CALL_LOG_ENTER;
    if (client_ == nullptr) {
        return InitClient();
    }
    return true;
}

bool MultimodalEventHandler::InitClient()
{
    CALL_LOG_ENTER;
    if (client_ != nullptr) {
        return true;
    }
    client_ = std::make_shared<MMIClient>();
    CHKPF(client_);
    client_->RegisterConnectedFunction(&OnConnected);
    if (!(client_->Start())) {
        MMI_HILOGE("The client fails to start");
        return false;
    }
    return true;
}

MMIClientPtr MultimodalEventHandler::GetMMIClient()
{
    if (client_ != nullptr) {
        return client_->GetSharedPtr();
    }
    MMI_HILOGE("Init client faild");
    return nullptr;
}

int32_t MultimodalEventHandler::GetDeviceIds(int32_t userData)
{
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }
    return EventManager.GetDeviceIds(userData);
}

int32_t MultimodalEventHandler::GetDevice(int32_t userData, int32_t deviceId)
{
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }
    return EventManager.GetDevice(userData, deviceId);
}

int32_t MultimodalEventHandler::GetKeystrokeAbility(int32_t userData, int32_t deviceId, std::vector<int32_t> keyCodes)
{
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }
    return EventManager.GetKeystrokeAbility(userData, deviceId, keyCodes);
}

int32_t MultimodalEventHandler::RegisterInputDeviceMonitor()
{
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }
    return EventManager.RegisterInputDeviceMonitor();
}

int32_t MultimodalEventHandler::UnRegisterInputDeviceMonitor()
{
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }
    return EventManager.UnRegisterInputDeviceMonitor();
}

int32_t MultimodalEventHandler::InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }
    return EventManager.InjectPointerEvent(pointerEvent);
}

int32_t MultimodalEventHandler::AddInterceptor(int32_t sourceType, int32_t id)
{
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }

    NetPacket pkt(MmiMessageId::ADD_EVENT_INTERCEPTOR);
    pkt << sourceType << id;
    client_->SendMessage(pkt);
    MMI_HILOGD("client add a touchpad event interceptor");
    return RET_OK;
}


int32_t MultimodalEventHandler::RemoveInterceptor(int32_t id)
{
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }

    NetPacket pkt(MmiMessageId::REMOVE_EVENT_INTERCEPTOR);
    pkt << id;
    client_->SendMessage(pkt);
    MMI_HILOGD("client remove a touchpad event interceptor");
    return RET_OK;
}

int32_t MultimodalEventHandler::AddInputEventMontior(int32_t keyEventType)
{
    CALL_LOG_ENTER;
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }
    NetPacket pkt(MmiMessageId::ADD_INPUT_EVENT_MONITOR);
    pkt << keyEventType;
    client_->SendMessage(pkt);
    return RET_OK;
}

void MultimodalEventHandler::RemoveInputEventMontior(int32_t keyEventType)
{
    CALL_LOG_ENTER;
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return;
    }
    NetPacket pkt(MmiMessageId::REMOVE_INPUT_EVENT_MONITOR);
    pkt << keyEventType;
    client_->SendMessage(pkt);
}

void MultimodalEventHandler::RemoveInputEventTouchpadMontior(int32_t pointerEventType)
{
    CALL_LOG_ENTER;
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return;
    }
    NetPacket pkt(MmiMessageId::REMOVE_INPUT_EVENT_TOUCHPAD_MONITOR);
    pkt << InputEvent::EVENT_TYPE_POINTER;
    client_->SendMessage(pkt);
}

int32_t MultimodalEventHandler::AddInputEventTouchpadMontior(int32_t pointerEventType)
{
    CALL_LOG_ENTER;
    if (!InitClient()) {
        MMI_HILOGE("Init client faild");
        return MMI_SERVICE_INVALID;
    }
    NetPacket pkt(MmiMessageId::ADD_INPUT_EVENT_TOUCHPAD_MONITOR);
    pkt << InputEvent::EVENT_TYPE_POINTER;
    MMI_HILOGE("send msg before");
    bool isSuc = client_->SendMessage(pkt);
    if (isSuc)
        MMI_HILOGD("sendAdd msg Success");
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
