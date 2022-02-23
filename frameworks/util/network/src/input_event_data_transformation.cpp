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
    const std::shared_ptr<KeyEvent> key, NetPacket &packet)
{
    CHKR((RET_OK == SerializeInputEvent(key, packet)), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(key->GetKeyCode()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(key->GetKeyAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    auto keys = key->GetKeyItems();
    int32_t size = keys.size();
    CHKR(packet.Write(size), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (const auto &item : keys) {
        CHKR(packet.Write(item.GetKeyCode()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetDownTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.IsPressed()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::NetPacketToKeyEvent(NetPacket &packet, std::shared_ptr<KeyEvent> key)
{
    CHKR((RET_OK == DeserializeInputEvent(packet, key)), STREAM_BUF_READ_FAIL, RET_ERR);
    int32_t data = 0;
    CHKR(packet.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetKeyCode(data);
    CHKR(packet.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetKeyAction(data);
    int32_t size = 0;
    CHKR(packet.Read(size), STREAM_BUF_READ_FAIL, RET_ERR);
    bool isPressed = false;
    for (int32_t i = 0; i < size; i++) {
        KeyEvent::KeyItem keyItem;
        CHKR(packet.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetKeyCode(data);
        int64_t datatime = 0;
        CHKR(packet.Read(datatime), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetDownTime(datatime);
        CHKR(packet.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetDeviceId(data);
        CHKR(packet.Read(isPressed), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetPressed(isPressed);
        key->AddKeyItem(keyItem);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::SerializeInputEvent(std::shared_ptr<InputEvent> event, NetPacket &packet)
{
    CHKPR(event, ERROR_NULL_POINTER);
    CHKR(packet.Write(event->GetEventType()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetActionTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetActionStartTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetTargetDisplayId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetTargetWindowId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetAgentWindowId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetBit()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializeInputEvent(NetPacket &packet, std::shared_ptr<InputEvent> event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t tField {  };
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetId(tField);
    int64_t rField = 0;
    CHKR(packet.Read(rField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetActionTime(rField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetAction(tField);
    CHKR(packet.Read(rField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetActionStartTime(rField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetDeviceId(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetTargetDisplayId(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetTargetWindowId(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetAgentWindowId(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetBit(tField);
    return RET_OK;
}

int32_t InputEventDataTransformation::Marshalling(std::shared_ptr<PointerEvent> event, NetPacket &packet)
{
    CHKPR(event, ERROR_NULL_POINTER);
    CHKR((RET_OK == SerializeInputEvent(event, packet)), STREAM_BUF_WRITE_FAIL, RET_ERR);

    CHKR(packet.Write(event->GetPointerAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetPointerId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetSourceType()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetButtonId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(packet.Write(event->GetAxes()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        CHKR(packet.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        CHKR(packet.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_PINCH)) {
        CHKR(packet.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
    }

    std::set<int32_t> pressedBtns { event->GetPressedButtons() };
    CHKR(packet.Write(pressedBtns.size()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (int32_t btnId : pressedBtns) {
        CHKR(packet.Write(btnId), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }

    std::vector<int32_t> pointerIds { event->GetPointersIdList() };
    CHKR(packet.Write(pointerIds.size()), STREAM_BUF_WRITE_FAIL, RET_ERR);

    for (const auto &pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        CHKR(event->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL, RET_ERR);

        CHKR(packet.Write(pointerId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetDownTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(static_cast<int32_t>(item.IsPressed())), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetGlobalX()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetGlobalY()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetLocalX()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetLocalY()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetWidth()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetHeight()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetPressure()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(packet.Write(item.GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }

    std::vector<int32_t> pressedKeys = event->GetPressedKeys();
    CHKR(packet.Write(pressedKeys.size()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (const auto &keyCode : pressedKeys) {
        CHKR(packet.Write(keyCode), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::Unmarshalling(NetPacket &packet, std::shared_ptr<PointerEvent> event)
{
    CHKR((RET_OK == DeserializeInputEvent(packet, event)),
        STREAM_BUF_READ_FAIL, RET_ERR);

    int32_t tField {  };
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetPointerAction(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetPointerId(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetSourceType(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetButtonId(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    double axisValue {  };
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        CHKR(packet.Read(axisValue), STREAM_BUF_READ_FAIL, RET_ERR);
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        CHKR(packet.Read(axisValue), STREAM_BUF_READ_FAIL, RET_ERR);
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_PINCH)) {
        CHKR(packet.Read(axisValue), STREAM_BUF_READ_FAIL, RET_ERR);
        event->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    }

    std::set<int32_t>::size_type nPressed {  };
    CHKR(packet.Read(nPressed), STREAM_BUF_READ_FAIL, RET_ERR);
    while (nPressed-- > 0) {
        CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
        event->SetButtonPressed(tField);
    }

    std::vector<int32_t>::size_type pointerCnt {  };
    CHKR(packet.Read(pointerCnt), STREAM_BUF_READ_FAIL, RET_ERR);

    while (pointerCnt-- > 0) {
        PointerEvent::PointerItem item;
        CHKR((RET_OK == DeserializePointerItem(packet, item)), STREAM_BUF_READ_FAIL, RET_ERR);
        event->AddPointerItem(item);
    }

    std::vector<int32_t> pressedKeys;
    std::vector<int32_t>::size_type pressedKeySize = 0;
    CHKR(packet.Read(pressedKeySize), STREAM_BUF_READ_FAIL, RET_ERR);
    while (pressedKeySize-- > 0) {
        CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
        pressedKeys.push_back(tField);
    }
    event->SetPressedKeys(pressedKeys);
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializePointerItem(NetPacket &packet, PointerEvent::PointerItem &item)
{
    int32_t tField {  };
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetPointerId(tField);
    int64_t rField = 0;
    CHKR(packet.Read(rField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetDownTime(rField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetPressed(static_cast<bool>(tField));
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetGlobalX(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetGlobalY(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetLocalX(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetLocalY(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetWidth(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetHeight(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetPressure(tField);
    CHKR(packet.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetDeviceId(tField);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS