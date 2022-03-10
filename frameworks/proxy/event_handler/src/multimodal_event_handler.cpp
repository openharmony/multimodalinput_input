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

#include "immi_token.h"
#include "input_event.h"
#include "input_manager_impl.h"
#include "mmi_client.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "MultimodalEventHandler"};
} // namespace

void OnConnected(const IfMMIClient& client)
{
    InputManagerImpl::GetInstance()->OnConnected();
}

MultimodalEventHandler::MultimodalEventHandler()
{
#ifdef OHOS_BUILD_MMI_DEBUG
    VerifyLogManagerRun();
#endif
}

int32_t MultimodalEventHandler::InjectEvent(const std::shared_ptr<KeyEvent> keyEventPtr)
{
    CHKPR(keyEventPtr, ERROR_NULL_POINTER);
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

bool MultimodalEventHandler::InitClient()
{
    CALL_LOG_ENTER;
    if (client_ != nullptr) {
        return true;
    }
    client_ = std::make_shared<MMIClient>();
    CHKPF(client_);
    cMsgHandler_ = std::make_shared<ClientMsgHandler>();
    CHKPF(cMsgHandler_);
    EventManager.SetClientHandle(client_);
    client_->RegisterConnectedFunction(&OnConnected);
    if (!(client_->Start(cMsgHandler_, true))) {
        MMI_LOGE("The client fails to start");
        return false;
    }
    return true;
}

MMIClientPtr MultimodalEventHandler::GetMMIClient()
{
    if (InitClient()) {
        return client_;
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
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }
    return EventManager.InjectPointerEvent(pointerEvent);
}

int32_t MultimodalEventHandler::AddInterceptor(int32_t sourceType, int32_t id)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }

    NetPacket pkt(MmiMessageId::ADD_EVENT_INTERCEPTOR);
    pkt << sourceType << id;
    client_->SendMessage(pkt);
    MMI_LOGD("client add a touchpad event interceptor");
    return RET_OK;
}


int32_t MultimodalEventHandler::RemoveInterceptor(int32_t id)
{
    if (!InitClient()) {
        return MMI_SERVICE_INVALID;
    }

    NetPacket pkt(MmiMessageId::REMOVE_EVENT_INTERCEPTOR);
    pkt << id;
    client_->SendMessage(pkt);
    MMI_LOGD("client remove a touchpad event interceptor");
    return RET_OK;
}

int32_t MultimodalEventHandler::AddInputEventMontior(int32_t keyEventType)
{
    CALL_LOG_ENTER;
    if (!InitClient()) {
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
        return MMI_SERVICE_INVALID;
    }
    NetPacket pkt(MmiMessageId::ADD_INPUT_EVENT_TOUCHPAD_MONITOR);
    pkt << InputEvent::EVENT_TYPE_POINTER;
    MMI_LOGE("send msg before");
    bool isSuc = client_->SendMessage(pkt);
    if (isSuc)
        MMI_LOGD("sendAdd msg Success");
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
