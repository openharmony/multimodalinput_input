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
    CHKR((RET_OK == SerializeInputEvent(key, pkt)), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(key->GetKeyCode()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(key->GetKeyAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    auto keys = key->GetKeyItems();
    int32_t size = keys.size();
    CHKR(pkt.Write(size), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (const auto &item : keys) {
        CHKR(pkt.Write(item.GetKeyCode()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetDownTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.IsPressed()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::NetPacketToKeyEvent(NetPacket &pkt, std::shared_ptr<KeyEvent> key)
{
    CHKR((RET_OK == DeserializeInputEvent(pkt, key)), STREAM_BUF_READ_FAIL, RET_ERR);
    int32_t data = 0;
    CHKR(pkt.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetKeyCode(data);
    CHKR(pkt.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetKeyAction(data);
    int32_t size = 0;
    CHKR(pkt.Read(size), STREAM_BUF_READ_FAIL, RET_ERR);
    bool isPressed = false;
    for (int32_t i = 0; i < size; i++) {
        KeyEvent::KeyItem keyItem;
        CHKR(pkt.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetKeyCode(data);
        int64_t datatime = 0;
        CHKR(pkt.Read(datatime), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetDownTime(datatime);
        CHKR(pkt.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetDeviceId(data);
        CHKR(pkt.Read(isPressed), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetPressed(isPressed);
        key->AddKeyItem(keyItem);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::SerializeInputEvent(std::shared_ptr<InputEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    CHKR(pkt.Write(event->GetEventType()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetActionTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetActionStartTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetTargetDisplayId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetTargetWindowId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetAgentWindowId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetFlag()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializeInputEvent(NetPacket &pkt, std::shared_ptr<InputEvent> event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t tField = 0;
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetId(tField);
    int64_t rField = 0;
    CHKR(pkt.Read(rField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetActionTime(rField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetAction(tField);
    CHKR(pkt.Read(rField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetActionStartTime(rField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetDeviceId(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetTargetDisplayId(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetTargetWindowId(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetAgentWindowId(tField);
    uint32_t tFlag = InputEvent::EVENT_FLAG_NONE;
    CHKR(pkt.Read(tFlag), STREAM_BUF_READ_FAIL, RET_ERR);
    event->AddFlag(tFlag);
    return RET_OK;
}

int32_t InputEventDataTransformation::Marshalling(std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    CHKR((RET_OK == SerializeInputEvent(event, pkt)), STREAM_BUF_WRITE_FAIL, RET_ERR);

    CHKR(pkt.Write(event->GetPointerAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetPointerId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetSourceType()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetButtonId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pkt.Write(event->GetAxes()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        CHKR(pkt.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        CHKR(pkt.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    if (event->HasAxis(PointerEvent::AXIS_TYPE_PINCH)) {
        CHKR(pkt.Write(event->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
    }

    std::set<int32_t> pressedBtns { event->GetPressedButtons() };
    CHKR(pkt.Write(pressedBtns.size()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (int32_t btnId : pressedBtns) {
        CHKR(pkt.Write(btnId), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }

    std::vector<int32_t> pointerIds { event->GetPointersIdList() };
    CHKR(pkt.Write(pointerIds.size()), STREAM_BUF_WRITE_FAIL, RET_ERR);

    for (const auto &pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        CHKR(event->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL, RET_ERR);

        CHKR(pkt.Write(pointerId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetDownTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(static_cast<int32_t>(item.IsPressed())), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetGlobalX()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetGlobalY()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetLocalX()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetLocalY()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetWidth()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetHeight()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetPressure()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pkt.Write(item.GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }

    std::vector<int32_t> pressedKeys = event->GetPressedKeys();
    CHKR(pkt.Write(pressedKeys.size()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (const auto &keyCode : pressedKeys) {
        CHKR(pkt.Write(keyCode), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::Unmarshalling(NetPacket &pkt, std::shared_ptr<PointerEvent> event)
{
    CHKR((RET_OK == DeserializeInputEvent(pkt, event)),
        STREAM_BUF_READ_FAIL, RET_ERR);

    int32_t tField {  };
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetPointerAction(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetPointerId(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetSourceType(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    event->SetButtonId(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    double axisValue {  };
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        CHKR(pkt.Read(axisValue), STREAM_BUF_READ_FAIL, RET_ERR);
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        CHKR(pkt.Read(axisValue), STREAM_BUF_READ_FAIL, RET_ERR);
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_PINCH)) {
        CHKR(pkt.Read(axisValue), STREAM_BUF_READ_FAIL, RET_ERR);
        event->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    }

    std::set<int32_t>::size_type nPressed {  };
    CHKR(pkt.Read(nPressed), STREAM_BUF_READ_FAIL, RET_ERR);
    while (nPressed-- > 0) {
        CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
        event->SetButtonPressed(tField);
    }

    std::vector<int32_t>::size_type pointerCnt {  };
    CHKR(pkt.Read(pointerCnt), STREAM_BUF_READ_FAIL, RET_ERR);

    while (pointerCnt-- > 0) {
        PointerEvent::PointerItem item;
        CHKR((RET_OK == DeserializePointerItem(pkt, item)), STREAM_BUF_READ_FAIL, RET_ERR);
        event->AddPointerItem(item);
    }

    std::vector<int32_t> pressedKeys;
    std::vector<int32_t>::size_type pressedKeySize = 0;
    CHKR(pkt.Read(pressedKeySize), STREAM_BUF_READ_FAIL, RET_ERR);
    while (pressedKeySize-- > 0) {
        CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
        pressedKeys.push_back(tField);
    }
    event->SetPressedKeys(pressedKeys);
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializePointerItem(NetPacket &pkt, PointerEvent::PointerItem &item)
{
    int32_t tField {  };
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetPointerId(tField);
    int64_t rField = 0;
    CHKR(pkt.Read(rField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetDownTime(rField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetPressed(static_cast<bool>(tField));
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetGlobalX(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetGlobalY(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetLocalX(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetLocalY(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetWidth(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetHeight(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetPressure(tField);
    CHKR(pkt.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetDeviceId(tField);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS