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
int32_t InputEventDataTransformation::KeyEventToNetPacket(
    const std::shared_ptr<KeyEvent> key, NetPacket &pkt)
{
    if (SerializeInputEvent(key, pkt) != RET_OK) {
        MMI_LOGE("Serialize input event failed");
        return RET_ERR;
    }
    if (!pkt.Write(key->GetKeyCode())) {
        MMI_LOGE("Packet write keyCode failed");
        return RET_ERR;
    }
    if (!pkt.Write(key->GetKeyAction())) {
        MMI_LOGE("Packet write keyAction failed");
        return RET_ERR;
    }
    auto keys = key->GetKeyItems();
    int32_t size = keys.size();
    if (!pkt.Write(size)) {
        MMI_LOGE("Packet write keys size failed");
        return RET_ERR;
    }
    for (const auto &item : keys) {
        if (!pkt.Write(item.GetKeyCode())) {
            MMI_LOGE("Packet write item keyCode failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetDownTime())) {
            MMI_LOGE("Packet write item downTime failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetDeviceId())) {
            MMI_LOGE("Packet write item device failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.IsPressed())) {
            MMI_LOGE("Packet write item isPressed failed");
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::NetPacketToKeyEvent(NetPacket &pkt, std::shared_ptr<KeyEvent> key)
{
    if (DeserializeInputEvent(pkt, key) != RET_OK) {
        MMI_LOGE("Deserialize input event failed");
        return RET_ERR;
    }
    int32_t data = 0;
    if (!pkt.Read(data)) {
        MMI_LOGE("Packet read keyCode failed");
        return RET_ERR;
    }
    key->SetKeyCode(data);
    if (!pkt.Read(data)) {
        MMI_LOGE("Packet read keyAction failed");
        return RET_ERR;
    }
    key->SetKeyAction(data);
    int32_t size = 0;
    if (!pkt.Read(size)) {
        MMI_LOGE("Packet read size failed");
        return RET_ERR;
    }
    bool isPressed = false;
    for (int32_t i = 0; i < size; i++) {
        KeyEvent::KeyItem keyItem;
        if (!pkt.Read(data)) {
            MMI_LOGE("Packet read item keyCode failed");
            return RET_ERR;
        }
        keyItem.SetKeyCode(data);
        int64_t datatime = 0;
        if (!pkt.Read(datatime)) {
            MMI_LOGE("Packet read item downTime failed");
            return RET_ERR;
        }
        keyItem.SetDownTime(datatime);
        if (!pkt.Read(data)) {
            MMI_LOGE("Packet read item device failed");
            return RET_ERR;
        }
        keyItem.SetDeviceId(data);
        if (!pkt.Read(isPressed)) {
            MMI_LOGE("Packet read item isPressed failed");
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
        MMI_LOGE("Packet write eventType failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetId())) {
        MMI_LOGE("Packet write event failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetActionTime())) {
        MMI_LOGE("Packet write actionTime failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetAction())) {
        MMI_LOGE("Packet write action failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetActionStartTime())) {
        MMI_LOGE("Packet write actionStartTime failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetDeviceId())) {
        MMI_LOGE("Packet write device failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetTargetDisplayId())) {
        MMI_LOGE("Packet write targetDisplay failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetTargetWindowId())) {
        MMI_LOGE("Packet write targetWindow failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetAgentWindowId())) {
        MMI_LOGE("Packet write agentWindow failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetFlag())) {
        MMI_LOGE("Packet write flag failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializeInputEvent(NetPacket &pkt, std::shared_ptr<InputEvent> event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t tField = 0;
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read data failed");
        return RET_ERR;
    }
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read event failed");
        return RET_ERR;
    }
    event->SetId(tField);
    int64_t rField = 0;
    if (!pkt.Read(rField)) {
        MMI_LOGE("Packet read actionTime failed");
        return RET_ERR;
    }
    event->SetActionTime(rField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read action failed");
        return RET_ERR;
    }
    event->SetAction(tField);
    if (!pkt.Read(rField)) {
        MMI_LOGE("Packet read actionStartTime failed");
        return RET_ERR;
    }
    event->SetActionStartTime(rField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read device failed");
        return RET_ERR;
    }
    event->SetDeviceId(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read targetDisplay failed");
        return RET_ERR;
    }
    event->SetTargetDisplayId(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read targetWindow failed");
        return RET_ERR;
    }
    event->SetTargetWindowId(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read agentWindow failed");
        return RET_ERR;
    }
    event->SetAgentWindowId(tField);
    uint32_t tFlag = InputEvent::EVENT_FLAG_NONE;
    if (!pkt.Read(tFlag)) {
        MMI_LOGE("Packet read tFlag failed");
        return RET_ERR;
    }
    event->AddFlag(tFlag);
    return RET_OK;
}

int32_t InputEventDataTransformation::Marshalling(std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    if (SerializeInputEvent(event, pkt) != RET_OK) {
        MMI_LOGE("Serialize input event failed");
        return RET_ERR;
    }

    if (!pkt.Write(event->GetPointerAction())) {
        MMI_LOGE("Packet write pointerAction failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetPointerId())) {
        MMI_LOGE("Packet write pointer failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetSourceType())) {
        MMI_LOGE("Packet write sourceType failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetButtonId())) {
        MMI_LOGE("Packet write button failed");
        return RET_ERR;
    }
    if (!pkt.Write(event->GetAxes())) {
        MMI_LOGE("Packet write axes failed");
        return RET_ERR;
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        if (!pkt.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL))) {
            MMI_LOGE("Packet write vertical scroll axis failed");
            return RET_ERR;
        }
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        if (!pkt.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL))) {
            MMI_LOGE("Packet write horizontal scroll axis failed");
            return RET_ERR;
        }
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_PINCH)) {
        if (!pkt.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH))) {
            MMI_LOGE("Packet write pinch axis failed");
            return RET_ERR;
        }
    }

    std::set<int32_t> pressedBtns { event->GetPressedButtons() };
    if (!pkt.Write(pressedBtns.size())) {
        MMI_LOGE("Packet write pressedBtns size failed");
        return RET_ERR;
    }
    for (int32_t btnId : pressedBtns) {
        if (!pkt.Write(btnId)) {
            MMI_LOGE("Packet write btn failed");
            return RET_ERR;
        }
    }

    std::vector<int32_t> pointerIds { event->GetPointersIdList() };
    if (!pkt.Write(pointerIds.size())) {
        MMI_LOGE("Packet write pointer size failed");
        return RET_ERR;
    }

    for (const auto &pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        if (!event->GetPointerItem(pointerId, item)) {
            MMI_LOGE("Get pointer item failed");
            return RET_ERR;
        }

        if (!pkt.Write(pointerId)) {
            MMI_LOGE("Packet write pointer failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetDownTime())) {
            MMI_LOGE("Packet write item downTime failed");
            return RET_ERR;
        }
        if (!pkt.Write(static_cast<int32_t>(item.IsPressed()))) {
            MMI_LOGE("Packet write item isPressed failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetGlobalX())) {
            MMI_LOGE("Packet write item globalX failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetGlobalY())) {
            MMI_LOGE("Packet write item globalY failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetLocalX())) {
            MMI_LOGE("Packet write item localX failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetLocalY())) {
            MMI_LOGE("Packet write item localY failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetWidth())) {
            MMI_LOGE("Packet write item width failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetHeight())) {
            MMI_LOGE("Packet write item height failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetPressure())) {
            MMI_LOGE("Packet write item pressure failed");
            return RET_ERR;
        }
        if (!pkt.Write(item.GetDeviceId())) {
            MMI_LOGE("Packet write item device failed");
            return RET_ERR;
        }
    }

    std::vector<int32_t> pressedKeys = event->GetPressedKeys();
    if (!pkt.Write(pressedKeys.size())) {
        MMI_LOGE("Packet write pressedKeys size failed");
        return RET_ERR;
    }
    for (const auto &keyCode : pressedKeys) {
        if (!pkt.Write(keyCode)) {
            MMI_LOGE("Packet write keyCode failed");
            return RET_ERR;
        }
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::Unmarshalling(NetPacket &pkt, std::shared_ptr<PointerEvent> event)
{
    if (DeserializeInputEvent(pkt, event) != RET_OK) {
        MMI_LOGE("Deserialize input event failed");
        return RET_ERR;
    }
    int32_t tField {  };
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read pointerAction failed");
        return RET_ERR;
    }
    event->SetPointerAction(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read pointer failed");
        return RET_ERR;
    }
    event->SetPointerId(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read sourceType failed");
        return RET_ERR;
    }
    event->SetSourceType(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read button failed");
        return RET_ERR;
    }
    event->SetButtonId(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read axis failed");
        return RET_ERR;
    }
    double axisValue {  };
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        if (!pkt.Read(axisValue)) {
            MMI_LOGE("Packet read vertical scroll axisValue failed");
            return RET_ERR;
        }
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        if (!pkt.Read(axisValue)) {
            MMI_LOGE("Packet read horizontal scroll axisValue failed");
            return RET_ERR;
        }
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_PINCH)) {
        if (!pkt.Read(axisValue)) {
            MMI_LOGE("Packet read pinch axisValue failed");
            return RET_ERR;
        }
        event->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    }

    std::set<int32_t>::size_type nPressed {  };
    if (!pkt.Read(nPressed)) {
        MMI_LOGE("Packet read nPressed failed");
        return RET_ERR;
    }
    while (nPressed-- > 0) {
        if (!pkt.Read(tField)) {
            MMI_LOGE("Packet read buttonPressed failed");
            return RET_ERR;
        }
        event->SetButtonPressed(tField);
    }

    std::vector<int32_t>::size_type pointerCnt {  };
    if (!pkt.Read(pointerCnt)) {
        MMI_LOGE("Packet read pointerCnt failed");
        return RET_ERR;
    }

    while (pointerCnt-- > 0) {
        PointerEvent::PointerItem item;
        if (DeserializePointerItem(pkt, item) != RET_OK) {
            MMI_LOGE("Deserialize pointer item failed");
            return RET_ERR;
        }
        event->AddPointerItem(item);
    }

    std::vector<int32_t> pressedKeys;
    std::vector<int32_t>::size_type pressedKeySize = 0;
    if (!pkt.Read(pressedKeySize)) {
        MMI_LOGE("Packet read pressedKeySize failed");
        return RET_ERR;
    }
    while (pressedKeySize-- > 0) {
        if (!pkt.Read(tField)) {
            MMI_LOGE("Packet read pressKey failed");
            return RET_ERR;
        }
        pressedKeys.push_back(tField);
    }
    event->SetPressedKeys(pressedKeys);
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializePointerItem(NetPacket &pkt, PointerEvent::PointerItem &item)
{
    int32_t tField {  };
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read pointer failed");
        return RET_ERR;
    }
    item.SetPointerId(tField);
    int64_t rField = 0;
    if (!pkt.Read(rField)) {
        MMI_LOGE("Packet read downTime failed");
        return RET_ERR;
    }
    item.SetDownTime(rField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read pressed failed");
        return RET_ERR;
    }
    item.SetPressed(static_cast<bool>(tField));
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read globalX failed");
        return RET_ERR;
    }
    item.SetGlobalX(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read globalY failed");
        return RET_ERR;
    }
    item.SetGlobalY(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read localX failed");
        return RET_ERR;
    }
    item.SetLocalX(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read localY failed");
        return RET_ERR;
    }
    item.SetLocalY(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read width failed");
        return RET_ERR;
    }
    item.SetWidth(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read height failed");
        return RET_ERR;
    }
    item.SetHeight(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read pressure failed");
        return RET_ERR;
    }
    item.SetPressure(tField);
    if (!pkt.Read(tField)) {
        MMI_LOGE("Packet read device failed");
        return RET_ERR;
    }
    item.SetDeviceId(tField);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS