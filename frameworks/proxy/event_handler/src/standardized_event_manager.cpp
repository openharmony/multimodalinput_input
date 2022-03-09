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

#include "standardized_event_manager.h"
#include <sstream>
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "immi_token.h"
#include "input_event_data_transformation.h"
#include "multimodal_event_handler.h"
#include "net_packet.h"
#include "proto.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, MMI_LOG_DOMAIN, "StandardizedEventManager"
};
} // namespace

StandardizedEventManager::StandardizedEventManager() {}

StandardizedEventManager::~StandardizedEventManager() {}

void StandardizedEventManager::SetClientHandle(MMIClientPtr client)
{
    CALL_LOG_ENTER;
    client_ = client;
}

int32_t StandardizedEventManager::SubscribeKeyEvent(
    const KeyEventInputSubscribeManager::SubscribeKeyEventInfo &subscribeInfo)
{
    CALL_LOG_ENTER;
    NetPacket pkt(MmiMessageId::SUBSCRIBE_KEY_EVENT);
    std::shared_ptr<KeyOption> keyOption = subscribeInfo.GetKeyOption();
    uint32_t preKeySize = keyOption->GetPreKeys().size();
    pkt << subscribeInfo.GetSubscribeId() << keyOption->GetFinalKey() << keyOption->IsFinalKeyDown()
    << keyOption->GetFinalKeyDownDuration() << preKeySize;

    std::set<int32_t> preKeys = keyOption->GetPreKeys();
    for (const auto &item : preKeys) {
        pkt << item;
    }
    if (MMIEventHdl.GetMMIClient() == nullptr) {
        MMI_LOGE("client init failed");
        return RET_ERR;
    }
    if (!SendMsg(pkt)) {
        MMI_LOGE("Client failed to send message");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t StandardizedEventManager::UnSubscribeKeyEvent(int32_t subscribeId)
{
    CALL_LOG_ENTER;
    NetPacket pkt(MmiMessageId::UNSUBSCRIBE_KEY_EVENT);
    pkt << subscribeId;
    if (MMIEventHdl.GetMMIClient() == nullptr) {
        MMI_LOGE("client init failed");
        return RET_ERR;
    }
    if (!SendMsg(pkt)) {
        MMI_LOGE("Client failed to send message");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t StandardizedEventManager::InjectionVirtual(bool isPressed, int32_t keyCode,
    int64_t keyDownDuration, int32_t maxKeyCode)
{
    CALL_LOG_ENTER;
    VirtualKey virtualEvent;
    virtualEvent.isPressed = isPressed;
    virtualEvent.keyCode = keyCode;
    virtualEvent.keyDownDuration = keyDownDuration;
    NetPacket pkt(MmiMessageId::ON_VIRTUAL_KEY);
    pkt << virtualEvent;
    if (!SendMsg(pkt)) {
        MMI_LOGE("Send virtual event Msg error");
        return RET_ERR;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t StandardizedEventManager::InjectEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_LOG_ENTER;
    CHKPR(key, RET_ERR);
    key->UpdateId();
    if (key->GetKeyCode() < 0) {
        MMI_LOGE("keyCode is invalid:%{public}u", key->GetKeyCode());
        return RET_ERR;
    }
    NetPacket pkt(MmiMessageId::INJECT_KEY_EVENT);
    int32_t errCode = InputEventDataTransformation::KeyEventToNetPacket(key, pkt);
    if (errCode != RET_OK) {
        MMI_LOGE("Serialization is Failed, errCode:%{public}u", errCode);
        return RET_ERR;
    }
    if (!SendMsg(pkt)) {
        MMI_LOGE("Send inject event Msg error");
        return RET_ERR;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t StandardizedEventManager::InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_LOG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    MMI_LOGD("Inject pointer event:");
    std::stringstream sStream;
    sStream << *pointerEvent;
    std::string sLine;
    while (std::getline(sStream, sLine)) {
        MMI_LOGD("%{public}s", sLine.c_str());
    }
    NetPacket pkt(MmiMessageId::INJECT_POINTER_EVENT);
    if (InputEventDataTransformation::Marshalling(pointerEvent, pkt) != RET_OK) {
        MMI_LOGE("Marshalling pointer event failed");
        return RET_ERR;
    }
    if (!SendMsg(pkt)) {
        MMI_LOGE("SendMsg failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t StandardizedEventManager::GetDeviceIds(int32_t userData)
{
    NetPacket pkt(MmiMessageId::INPUT_DEVICE_IDS);
    pkt << userData;
    return SendMsg(pkt);
}

int32_t StandardizedEventManager::GetDevice(int32_t userData, int32_t deviceId)
{
    NetPacket pkt(MmiMessageId::INPUT_DEVICE);
    pkt << userData << deviceId;
    return SendMsg(pkt);
}

bool StandardizedEventManager::SendMsg(NetPacket& pkt) const
{
    CHKPF(client_);
    return client_->SendMessage(pkt);
}
} // namespace MMI
} // namespace OHOS
