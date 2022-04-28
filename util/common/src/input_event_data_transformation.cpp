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

#include "input_event_data_transformation.h"

#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "KeyEventDataTransformation" };
} // namespace

int32_t InputEventDataTransformation::KeyEventToNetPacket(
    const std::shared_ptr<KeyEvent> key, NetPacket &pkt)
{
    if (SerializeInputEvent(key, pkt) != RET_OK) {
        MMI_HILOGE("Serialize input event failed");
        return RET_ERR;
    }
    if (!pkt.Write(key->GetKeyCode())) {
        MMI_HILOGE("Packet write keyCode failed");
        return RET_ERR;
    }
    if (!pkt.Write(key->GetKeyAction())) {
        MMI_HILOGE("Packet write keyAction failed");
        return RET_ERR;
    }
    auto keys = key->GetKeyItems();
    int32_t size = static_cast<int32_t>(keys.size());
    if (!pkt.Write(size)) {
        MMI_HILOGE("Packet write keys size failed");
        return RET_ERR;
    }
    for (const auto &item : keys) {
        if (!pkt.Write(item.GetKeyCode())) {
            MMI_HILOGE("Packet write item keyCode failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetDownTime())) {
            MMI_HILOGE("Packet write item downTime failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetDeviceId())) {
            MMI_HILOGE("Packet write item device failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.IsPressed())) {
            MMI_HILOGE("Packet write item isPressed failed");
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::NetPacketToKeyEvent(NetPacket &pkt, std::shared_ptr<KeyEvent> key)
{
    if (DeserializeInputEvent(pkt, key) != RET_OK) {
        MMI_HILOGE("Deserialize input event failed");
        return RET_ERR;
    }
    int32_t data = 0;
    if (!pkt.Read(data)) {
        MMI_HILOGE("Packet read keyCode failed");
        return RET_ERR;
    }
    key->SetKeyCode(data);
    if (!pkt.Read(data)) {
        MMI_HILOGE("Packet read keyAction failed");
        return RET_ERR;
    }
    key->SetKeyAction(data);
    int32_t size = 0;
    if (!pkt.Read(size)) {
        MMI_HILOGE("Packet read size failed");
        return RET_ERR;
    }
    bool isPressed = false;
    for (int32_t i = 0; i < size; i++) {
        KeyEvent::KeyItem keyItem;
        if (!pkt.Read(data)) {
            MMI_HILOGE("Packet read item keyCode failed");
            return RET_ERR;
        }
        keyItem.SetKeyCode(data);
        int64_t datatime = 0;
        if (!pkt.Read(datatime)) {
            MMI_HILOGE("Packet read item downTime failed");
            return RET_ERR;
        }
        keyItem.SetDownTime(datatime);
        if (!pkt.Read(data)) {
            MMI_HILOGE("Packet read item device failed");
            return RET_ERR;
        }
        keyItem.SetDeviceId(data);
        if (!pkt.Read(isPressed)) {
            MMI_HILOGE("Packet read item isPressed failed");
            return RET_ERR;
        }
        keyItem.SetPressed(isPressed);
        key->AddKeyItem(keyItem);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::SerializeInputEvent(std::shared_ptr<InputEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    if (!pkt.Write(event->GetEventType())) {
        MMI_HILOGE("Packet write eventType failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetId())) {
        MMI_HILOGE("Packet write event failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetActionTime())) {
        MMI_HILOGE("Packet write actionTime failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetAction())) {
        MMI_HILOGE("Packet write action failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetActionStartTime())) {
        MMI_HILOGE("Packet write actionStartTime failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetDeviceId())) {
        MMI_HILOGE("Packet write device failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetTargetDisplayId())) {
        MMI_HILOGE("Packet write targetDisplay failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetTargetWindowId())) {
        MMI_HILOGE("Packet write targetWindow failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetAgentWindowId())) {
        MMI_HILOGE("Packet write agentWindow failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetFlag())) {
        MMI_HILOGE("Packet write flag failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializeInputEvent(NetPacket &pkt, std::shared_ptr<InputEvent> event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t tField = 0;
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read data failed");
        return RET_ERR;
    }
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read event failed");
        return RET_ERR;
    }
    event->SetId(tField);
    int64_t rField = 0;
    if (!pkt.Read(rField)) {
        MMI_HILOGE("Packet read actionTime failed");
        return RET_ERR;
    }
    event->SetActionTime(rField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read action failed");
        return RET_ERR;
    }
    event->SetAction(tField);
    if (!pkt.Read(rField)) {
        MMI_HILOGE("Packet read actionStartTime failed");
        return RET_ERR;
    }
    event->SetActionStartTime(rField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read device failed");
        return RET_ERR;
    }
    event->SetDeviceId(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read targetDisplay failed");
        return RET_ERR;
    }
    event->SetTargetDisplayId(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read targetWindow failed");
        return RET_ERR;
    }
    event->SetTargetWindowId(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read agentWindow failed");
        return RET_ERR;
    }
    event->SetAgentWindowId(tField);
    uint32_t tFlag = InputEvent::EVENT_FLAG_NONE;
    if (!pkt.Read(tFlag)) {
        MMI_HILOGE("Packet read tFlag failed");
        return RET_ERR;
    }
    event->AddFlag(tFlag);
    return RET_OK;
}

int32_t InputEventDataTransformation::Marshalling(std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    if (SerializeInputEvent(event, pkt) != RET_OK) {
        MMI_HILOGE("Serialize input event failed");
        return RET_ERR;
    }

    pkt << event->GetPointerAction() << event->GetPointerId() << event->GetSourceType() << event->GetButtonId()
        << event->GetAxes();

    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        pkt << event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL);
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        pkt << event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL);
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_PINCH)) {
        pkt << event->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH);
    }

    std::set<int32_t> pressedBtns { event->GetPressedButtons() };
    pkt << pressedBtns.size();
    for (int32_t btnId : pressedBtns) {
        pkt << btnId;
    }

    std::vector<int32_t> pointerIds { event->GetPointersIdList() };
    pkt << pointerIds.size();
    for (const auto &pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        if (!event->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Get pointer item failed");
            return RET_ERR;
        }
        if (SerializePointerItem(pkt, item) != RET_OK) {
            MMI_HILOGE("Serialize pointer item failed");
            return RET_ERR;
        }
    }

    std::vector<int32_t> pressedKeys = event->GetPressedKeys();
    pkt << pressedKeys.size();
    for (const auto &keyCode : pressedKeys) {
        pkt << keyCode;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Marshalling pointer event failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::Unmarshalling(NetPacket &pkt, std::shared_ptr<PointerEvent> event)
{
    if (DeserializeInputEvent(pkt, event) != RET_OK) {
        MMI_HILOGE("Deserialize input event failed");
        return RET_ERR;
    }
    int32_t tField;
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read pointerAction failed");
        return RET_ERR;
    }
    event->SetPointerAction(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read pointer failed");
        return RET_ERR;
    }
    event->SetPointerId(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read sourceType failed");
        return RET_ERR;
    }
    event->SetSourceType(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read button failed");
        return RET_ERR;
    }
    event->SetButtonId(tField);
    uint32_t tAxes;
    if (!pkt.Read(tAxes)) {
        MMI_HILOGE("Packet read axis failed");
        return RET_ERR;
    }
    double axisValue;
    if (PointerEvent::HasAxis(tAxes, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        if (!pkt.Read(axisValue)) {
            MMI_HILOGE("Packet read vertical scroll axisValue failed");
            return RET_ERR;
        }
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (PointerEvent::HasAxis(tAxes, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        if (!pkt.Read(axisValue)) {
            MMI_HILOGE("Packet read horizontal scroll axisValue failed");
            return RET_ERR;
        }
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    if (PointerEvent::HasAxis(tAxes, PointerEvent::AXIS_TYPE_PINCH)) {
        if (!pkt.Read(axisValue)) {
            MMI_HILOGE("Packet read pinch axisValue failed");
            return RET_ERR;
        }
        event->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    }

    std::set<int32_t>::size_type nPressed;
    if (!pkt.Read(nPressed)) {
        MMI_HILOGE("Packet read nPressed failed");
        return RET_ERR;
    }
    while (nPressed-- > 0) {
        if (!pkt.Read(tField)) {
            MMI_HILOGE("Packet read buttonPressed failed");
            return RET_ERR;
        }
        event->SetButtonPressed(tField);
    }

    std::vector<int32_t>::size_type pointerCnt;
    if (!pkt.Read(pointerCnt)) {
        MMI_HILOGE("Packet read pointerCnt failed");
        return RET_ERR;
    }

    while (pointerCnt-- > 0) {
        PointerEvent::PointerItem item;
        if (DeserializePointerItem(pkt, item) != RET_OK) {
            MMI_HILOGE("Deserialize pointer item failed");
            return RET_ERR;
        }
        event->AddPointerItem(item);
    }

    std::vector<int32_t> pressedKeys;
    std::vector<int32_t>::size_type pressedKeySize;
    if (!pkt.Read(pressedKeySize)) {
        MMI_HILOGE("Packet read pressedKeySize failed");
        return RET_ERR;
    }
    while (pressedKeySize-- > 0) {
        if (!pkt.Read(tField)) {
            MMI_HILOGE("Packet read pressKey failed");
            return RET_ERR;
        }
        pressedKeys.push_back(tField);
    }
    event->SetPressedKeys(pressedKeys);
    return RET_OK;
}

int32_t InputEventDataTransformation::SerializePointerItem(NetPacket &pkt, PointerEvent::PointerItem &item)
{
    pkt << item;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write pointer item failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializePointerItem(NetPacket &pkt, PointerEvent::PointerItem &item)
{
    pkt >> item;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read pointer item failed");
        return RET_ERR;
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS