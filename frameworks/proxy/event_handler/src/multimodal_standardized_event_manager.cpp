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

#include "multimodal_standardized_event_manager.h"
#include <cinttypes>
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "immi_token.h"
#include "input_event_data_transformation.h"
#include "multimodal_event_handler.h"
#include "net_packet.h"
#include "proto.h"

namespace OHOS {
namespace MMI {
    namespace {
        constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
            LOG_CORE, MMI_LOG_DOMAIN, "MultimodalStandardizedEventManager"
        };
    }

MultimodalStandardizedEventManager::MultimodalStandardizedEventManager() {}

MultimodalStandardizedEventManager::~MultimodalStandardizedEventManager() {}

void MultimodalStandardizedEventManager::SetClientHandle(MMIClientPtr client)
{
    MMI_LOGD("enter");
    client_ = client;
}

int32_t MultimodalStandardizedEventManager::SubscribeKeyEvent(
    const KeyEventInputSubscribeManager::SubscribeKeyEventInfo &subscribeInfo)
{
    MMI_LOGD("Enter");
    OHOS::MMI::NetPacket pkt(MmiMessageId::SUBSCRIBE_KEY_EVENT);
    std::shared_ptr<OHOS::MMI::KeyOption> keyOption = subscribeInfo.GetKeyOption();
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

int32_t MultimodalStandardizedEventManager::UnSubscribeKeyEvent(int32_t subscribeId)
{
    MMI_LOGD("Enter");
    OHOS::MMI::NetPacket pkt(MmiMessageId::UNSUBSCRIBE_KEY_EVENT);
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

int32_t MultimodalStandardizedEventManager::InjectionVirtual(bool isPressed, int32_t keyCode,
                                                             int32_t keyDownDuration, int32_t maxKeyCode)
{
    MMI_LOGD("Enter");
    VirtualKey virtualEvent;
    virtualEvent.isPressed = isPressed;
    virtualEvent.keyCode = keyCode;
    virtualEvent.keyDownDuration = keyDownDuration;
    OHOS::MMI::NetPacket pkt(MmiMessageId::ON_VIRTUAL_KEY);
    pkt << virtualEvent;
    if (!SendMsg(pkt)) {
        MMI_LOGE("Send virtual event Msg error");
        return RET_ERR;
    }
    MMI_LOGD("leave");
    return RET_OK;
}

int32_t MultimodalStandardizedEventManager::InjectEvent(const std::shared_ptr<KeyEvent> key)
{
    MMI_LOGD("begin");
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

int32_t MultimodalStandardizedEventManager::InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent)
{
    MMI_LOGD("enter");
    CHKPR(pointerEvent, RET_ERR);
    std::vector<int32_t> pointerIds { pointerEvent->GetPointersIdList() };
    MMI_LOGD("Pointer event dispatcher of client:eventType:%{public}s,actionTime:%{public}" PRId64 ","
             "action:%{public}d,actionStartTime:%{public}" PRId64 ","
             "flag:%{public}u,pointerAction:%{public}s,sourceType:%{public}s,"
             "VerticalAxisValue:%{public}f,HorizontalAxisValue:%{public}f,pointerCount:%{public}zu",
             pointerEvent->DumpEventType(), pointerEvent->GetActionTime(),
             pointerEvent->GetAction(), pointerEvent->GetActionStartTime(),
             pointerEvent->GetFlag(), pointerEvent->DumpPointerAction(),
             pointerEvent->DumpSourceType(),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL),
             pointerEvent->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL),
             pointerIds.size());

    for (const auto &pointerId : pointerIds) {
        OHOS::MMI::PointerEvent::PointerItem item;
        if (!pointerEvent->GetPointerItem(pointerId, item)) {
            MMI_LOGE("Get pointer item failed. pointer:%{public}d", pointerId);
            return RET_ERR;
        }
        MMI_LOGD("DownTime:%{public}" PRId64 ",isPressed:%{public}s,"
                "globalX:%{public}d,globalY:%{public}d,localX:%{public}d,localY:%{public}d,"
                "width:%{public}d,height:%{public}d,pressure:%{public}d",
                 item.GetDownTime(), (item.IsPressed() ? "true" : "false"),
                 item.GetGlobalX(), item.GetGlobalY(), item.GetLocalX(), item.GetLocalY(),
                 item.GetWidth(), item.GetHeight(), item.GetPressure());
    }
    std::vector<int32_t> pressedKeys = pointerEvent->GetPressedKeys();
    for (auto &keyCode : pressedKeys) {
        MMI_LOGI("Pressed keyCode:%{public}d", keyCode);
    }
    OHOS::MMI::NetPacket pkt(MmiMessageId::INJECT_POINTER_EVENT);
    if (InputEventDataTransformation::Marshalling(pointerEvent, pkt) != RET_OK) {
        MMI_LOGE("Marshalling pointer event failed");
        return RET_ERR;
    }
    MMI_LOGD("leave");
    if (!SendMsg(pkt)) {
        MMI_LOGE("SendMsg failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalStandardizedEventManager::GetDeviceIds(int32_t userData)
{
    OHOS::MMI::NetPacket pkt(MmiMessageId::INPUT_DEVICE_IDS);
    pkt << userData;
    return SendMsg(pkt);
}

int32_t MultimodalStandardizedEventManager::GetDevice(int32_t userData, int32_t deviceId)
{
    OHOS::MMI::NetPacket pkt(MmiMessageId::INPUT_DEVICE);
    pkt << userData << deviceId;
    return SendMsg(pkt);
}

bool MultimodalStandardizedEventManager::SendMsg(NetPacket& pkt) const
{
    CHKPF(client_);
    return client_->SendMessage(pkt);
}
} // namespace MMI
} // namespace OHOS
