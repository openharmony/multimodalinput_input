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

    if (!pkt.Write(event->GetPointerAction())) {
        MMI_HILOGE("Packet write pointerAction failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetPointerId())) {
        MMI_HILOGE("Packet write pointer failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetSourceType())) {
        MMI_HILOGE("Packet write sourceType failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetButtonId())) {
        MMI_HILOGE("Packet write button failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetAxes())) {
        MMI_HILOGE("Packet write axes failed");
        return RET_ERR;
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        if (!pkt.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL))) {
            MMI_HILOGE("Packet write vertical scroll axis failed");
            return RET_ERR;
        }
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        if (!pkt.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL))) {
            MMI_HILOGE("Packet write horizontal scroll axis failed");
            return RET_ERR;
        }
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_PINCH)) {
        if (!pkt.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH))) {
            MMI_HILOGE("Packet write pinch axis failed");
            return RET_ERR;
        }
    }

    std::set<int32_t> pressedBtns { event->GetPressedButtons() };
    if (!pkt.Write(pressedBtns.size())) {
        MMI_HILOGE("Packet write pressedBtns size failed");
        return RET_ERR;
    }
    for (int32_t btnId : pressedBtns) {
        if (!pkt.Write(btnId)) {
            MMI_HILOGE("Packet write btn failed");
            return RET_ERR;
        }
    }

    std::vector<int32_t> pointerIds { event->GetPointersIdList() };
    if (!pkt.Write(pointerIds.size())) {
        MMI_HILOGE("Packet write pointer size failed");
        return RET_ERR;
    }

    for (const auto &pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        if (!event->GetPointerItem(pointerId, item)) {
            MMI_HILOGE("Get pointer item failed");
            return RET_ERR;
        }

        if (!pkt.Write(pointerId)) {
            MMI_HILOGE("Packet write pointer failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetDownTime())) {
            MMI_HILOGE("Packet write item downTime failed");
            return RET_ERR;
        }
        if (!pkt.Write(static_cast<int32_t>(item.IsPressed()))) {
            MMI_HILOGE("Packet write item isPressed failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetGlobalX())) {
            MMI_HILOGE("Packet write item globalX failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetGlobalY())) {
            MMI_HILOGE("Packet write item globalY failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetLocalX())) {
            MMI_HILOGE("Packet write item localX failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetLocalY())) {
            MMI_HILOGE("Packet write item localY failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetWidth())) {
            MMI_HILOGE("Packet write item width failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetHeight())) {
            MMI_HILOGE("Packet write item height failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetTiltX())) {
            MMI_HILOGE("Packet write item tiltX failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetTiltY())) {
            MMI_HILOGE("Packet write item tiltY failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetPressure())) {
            MMI_HILOGE("Packet write item pressure failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetDeviceId())) {
            MMI_HILOGE("Packet write item device failed");
            return RET_ERR;
        }
    }

    std::vector<int32_t> pressedKeys = event->GetPressedKeys();
    if (!pkt.Write(pressedKeys.size())) {
        MMI_HILOGE("Packet write pressedKeys size failed");
        return RET_ERR;
    }
    for (const auto &keyCode : pressedKeys) {
        if (!pkt.Write(keyCode)) {
            MMI_HILOGE("Packet write keyCode failed");
            return RET_ERR;
        }
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

int32_t InputEventDataTransformation::DeserializePointerItem(NetPacket &pkt, PointerEvent::PointerItem &item)
{
    int32_t tField;
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read pointer failed");
        return RET_ERR;
    }
    item.SetPointerId(tField);
    int64_t rField;
    if (!pkt.Read(rField)) {
        MMI_HILOGE("Packet read downTime failed");
        return RET_ERR;
    }
    item.SetDownTime(rField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read pressed failed");
        return RET_ERR;
    }
    item.SetPressed(static_cast<bool>(tField));
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read globalX failed");
        return RET_ERR;
    }
    item.SetGlobalX(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read globalY failed");
        return RET_ERR;
    }
    item.SetGlobalY(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read localX failed");
        return RET_ERR;
    }
    item.SetLocalX(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read localY failed");
        return RET_ERR;
    }
    item.SetLocalY(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read width failed");
        return RET_ERR;
    }
    item.SetWidth(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read height failed");
        return RET_ERR;
    }
    item.SetHeight(tField);
    double fField;
    if (!pkt.Read(fField)) {
        MMI_HILOGE("Packet read tiltX failed");
        return RET_ERR;
    }
    item.SetTiltX(fField);
    if (!pkt.Read(fField)) {
        MMI_HILOGE("Packet read tiltY failed");
        return RET_ERR;
    }
    item.SetTiltY(fField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read pressure failed");
        return RET_ERR;
    }
    item.SetPressure(tField);
    if (!pkt.Read(tField)) {
        MMI_HILOGE("Packet read device failed");
        return RET_ERR;
    }
    item.SetDeviceId(tField);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS