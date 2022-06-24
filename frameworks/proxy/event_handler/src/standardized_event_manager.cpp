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
#include "net_packet.h"
#include "proto.h"
#include "util.h"

#include "input_event_data_transformation.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

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
    return MultimodalInputConnMgr->SubscribeKeyEvent(subscribeInfo.GetSubscribeId(), subscribeInfo.GetKeyOption());
}

int32_t StandardizedEventManager::UnSubscribeKeyEvent(int32_t subscribeId)
{
    CALL_LOG_ENTER;
    return MultimodalInputConnMgr->UnsubscribeKeyEvent(subscribeId);
}

int32_t StandardizedEventManager::InjectEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_LOG_ENTER;
    CHKPR(keyEvent, RET_ERR);
    keyEvent->UpdateId();
    if (keyEvent->GetKeyCode() < 0) {
        MMI_HILOGE("keyCode is invalid:%{public}u", keyEvent->GetKeyCode());
        return RET_ERR;
    }
    int32_t ret = MultimodalInputConnMgr->InjectKeyEvent(keyEvent);
    if (ret != 0) {
        MMI_HILOGE("send to server fail, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

int32_t StandardizedEventManager::InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_LOG_ENTER;
    CHKPR(pointerEvent, ERROR_NULL_POINTER);
    MMI_HILOGD("Inject pointer event:");
    std::stringstream sStream;
    sStream << *pointerEvent;
    std::string sLine;
    while (std::getline(sStream, sLine)) {
        MMI_HILOGD("%{public}s", sLine.c_str());
    }
    int32_t ret = MultimodalInputConnMgr->InjectPointerEvent(pointerEvent);
    if (ret != 0) {
        MMI_HILOGE("send to server fail, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
int32_t StandardizedEventManager::MoveMouseEvent(int32_t offsetX, int32_t offsetY)
{
    CALL_LOG_ENTER;
    int32_t ret = MultimodalInputConnMgr->MoveMouseEvent(offsetX, offsetY);
    if (ret != 0) {
        MMI_HILOGE("send to server fail, ret:%{public}d", ret);
        return RET_ERR;
    }
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

int32_t StandardizedEventManager::GetDeviceIds(int32_t userData)
{
    NetPacket pkt(MmiMessageId::INPUT_DEVICE_IDS);
    pkt << userData;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write userData failed");
        return RET_ERR;
    }
    return SendMsg(pkt);
}

int32_t StandardizedEventManager::GetDevice(int32_t userData, int32_t deviceId)
{
    NetPacket pkt(MmiMessageId::INPUT_DEVICE);
    pkt << userData << deviceId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write userData failed");
        return RET_ERR;
    }
    return SendMsg(pkt);
}

int32_t StandardizedEventManager::SupportKeys(int32_t userData, int32_t deviceId, std::vector<int32_t> keyCodes)
{
    NetPacket pkt(MmiMessageId::INPUT_DEVICE_KEYSTROKE_ABILITY);
    pkt << userData << deviceId << keyCodes;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write keyCodes failed");
        return RET_ERR;
    }
    return SendMsg(pkt);
}

int32_t StandardizedEventManager::GetKeyboardType(int32_t userData, int32_t deviceId) const
{
    NetPacket pkt(MmiMessageId::INPUT_DEVICE_KEYBOARD_TYPE);
    pkt << userData << deviceId;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write userData failed");
        return PACKET_WRITE_FAIL;
    }
    return SendMsg(pkt);
}

int32_t StandardizedEventManager::RegisterInputDeviceMonitor()
{
    NetPacket pkt(MmiMessageId::ADD_INPUT_DEVICE_MONITOR);
    return SendMsg(pkt);
}

int32_t StandardizedEventManager::UnRegisterInputDeviceMonitor()
{
    NetPacket pkt(MmiMessageId::REMOVE_INPUT_DEVICE_MONITOR);
    return SendMsg(pkt);
}

bool StandardizedEventManager::SendMsg(NetPacket& pkt) const
{
    CHKPF(client_);
    return client_->SendMessage(pkt);
}
} // namespace MMI
} // namespace OHOS
