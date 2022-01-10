/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
    const std::shared_ptr<OHOS::MMI::KeyEvent> key, NetPacket &pck)
{
    CHKR(pck.Write(key->GetId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetActionTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetActionStartTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetTargetDisplayId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetAgentWindowId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetTargetWindowId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetFlag()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetKeyCode()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(key->GetKeyAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    auto keys = key->GetKeyItems();
    int32_t size = keys.size();
    CHKR(pck.Write(size), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (auto &item : keys) {
        CHKR(pck.Write(item.GetKeyCode()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetDownTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.IsPressed()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    return RET_OK;
}
int32_t InputEventDataTransformation::NetPacketToKeyEvent(
    std::shared_ptr<OHOS::MMI::KeyEvent> key, NetPacket &pck)
{
    int32_t data = 0;
    int32_t size = 0;
    bool isPressed = false;
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetId(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetActionTime(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetAction(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetActionStartTime(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetDeviceId(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetTargetDisplayId(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetAgentWindowId(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetTargetWindowId(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->AddFlag(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetKeyCode(data);
    CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
    key->SetKeyAction(data);
    CHKR(pck.Read(size), STREAM_BUF_READ_FAIL, RET_ERR);
    for (int32_t i = 0; i < size; i++) {
        OHOS::MMI::KeyEvent::KeyItem keyItem;
        CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetKeyCode(data);
        CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetDownTime(data);
        CHKR(pck.Read(data), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetDeviceId(data);
        CHKR(pck.Read(isPressed), STREAM_BUF_READ_FAIL, RET_ERR);
        keyItem.SetPressed(isPressed);
        key->AddKeyItem(keyItem);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::SerializeInputEvent(std::shared_ptr<InputEvent> inputE, NetPacket &pck)
{
    CHKR(pck.Write(inputE->GetEventType()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(inputE->GetId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(inputE->GetActionTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(inputE->GetAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(inputE->GetActionStartTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(inputE->GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(inputE->GetTargetDisplayId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(inputE->GetTargetWindowId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(inputE->GetAgentWindowId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(inputE->GetFlag()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializeInputEvent(bool skipId,
    std::shared_ptr<InputEvent> inputE, NetPacket &pck)
{
    int32_t tField {  };
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    if (!skipId)
        inputE->SetId(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    inputE->SetActionTime(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    inputE->SetAction(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    inputE->SetActionStartTime(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    inputE->SetDeviceId(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    inputE->SetTargetDisplayId(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    inputE->SetTargetWindowId(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    inputE->SetAgentWindowId(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    inputE->AddFlag(tField);
    return RET_OK;
}

int32_t InputEventDataTransformation::SerializePointerEvent(std::shared_ptr<PointerEvent> pointerE, NetPacket &pck)
{
    CHKR((RET_OK == SerializeInputEvent(pointerE, pck)), STREAM_BUF_WRITE_FAIL, RET_ERR);

    CHKR(pck.Write(pointerE->GetPointerAction()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(pointerE->GetPointerId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(pointerE->GetSourceType()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(pointerE->GetButtonId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    CHKR(pck.Write(pointerE->GetAxes()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    if (pointerE->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        CHKR(pck.Write(pointerE->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    if (pointerE->HasAxis(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        CHKR(pck.Write(pointerE->GetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    if (pointerE->HasAxis(PointerEvent::AXIS_TYPE_PINCH)) {
        CHKR(pck.Write(pointerE->GetAxisValue(PointerEvent::AXIS_TYPE_PINCH)),
            STREAM_BUF_WRITE_FAIL, RET_ERR);
    }

    std::set<int32_t> pressedBtns { pointerE->GetPressedButtons() };
    CHKR(pck.Write(pressedBtns.size()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (int32_t btnId : pressedBtns) {
        CHKR(pck.Write(btnId), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }

    std::vector<int32_t> pointerIds { pointerE->GetPointersIdList() };
    CHKR(pck.Write(pointerIds.size()), STREAM_BUF_WRITE_FAIL, RET_ERR);

    for (int32_t pointerId : pointerIds) {
        PointerEvent::PointerItem item;
        CHKR(pointerE->GetPointerItem(pointerId, item), PARAM_INPUT_FAIL, RET_ERR);

        CHKR(pck.Write(pointerId), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetDownTime()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(static_cast<int32_t>(item.IsPressed())), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetGlobalX()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetGlobalY()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetLocalX()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetLocalY()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetWidth()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetHeight()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetPressure()), STREAM_BUF_WRITE_FAIL, RET_ERR);
        CHKR(pck.Write(item.GetDeviceId()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }

    std::vector<int32_t> pressedKeys = pointerE->GetPressedKeys();
    CHKR(pck.Write(pressedKeys.size()), STREAM_BUF_WRITE_FAIL, RET_ERR);
    for (int32_t keyCode : pressedKeys) {
        CHKR(pck.Write(keyCode), STREAM_BUF_WRITE_FAIL, RET_ERR);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializePointerEvent(bool skipId,
    std::shared_ptr<PointerEvent> pointerE, NetPacket &pck)
{
    CHKR((RET_OK == DeserializeInputEvent(skipId, pointerE, pck)),
        STREAM_BUF_READ_FAIL, RET_ERR);

    int32_t tField {  };
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    pointerE->SetPointerAction(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    pointerE->SetPointerId(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    pointerE->SetSourceType(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    pointerE->SetButtonId(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    double axisValue {  };
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        CHKR(pck.Read(axisValue), STREAM_BUF_READ_FAIL, RET_ERR);
        pointerE->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        CHKR(pck.Read(axisValue), STREAM_BUF_READ_FAIL, RET_ERR);
        pointerE->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    if (PointerEvent::HasAxis(tField, PointerEvent::AXIS_TYPE_PINCH)) {
        CHKR(pck.Read(axisValue), STREAM_BUF_READ_FAIL, RET_ERR);
        pointerE->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    }

    std::set<int32_t>::size_type nPressed {  };
    CHKR(pck.Read(nPressed), STREAM_BUF_READ_FAIL, RET_ERR);
    while (nPressed-- > 0) {
        CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
        pointerE->SetButtonPressed(tField);
    }

    std::vector<int32_t>::size_type pointerCnt {  };
    CHKR(pck.Read(pointerCnt), STREAM_BUF_READ_FAIL, RET_ERR);

    while (pointerCnt-- > 0) {
        PointerEvent::PointerItem item;
        CHKR((RET_OK == DeserializePointerItem(item, pck)), STREAM_BUF_READ_FAIL, RET_ERR);
        pointerE->AddPointerItem(item);
    }

    std::vector<int32_t> pressedKeys;
    std::vector<int32_t>::size_type pressedKeySize = 0;
    CHKR(pck.Read(pressedKeySize), STREAM_BUF_READ_FAIL, RET_ERR);
    while (pressedKeySize-- > 0) {
        CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
        pressedKeys.push_back(tField);
    }
    pointerE->SetPressedKeys(pressedKeys);
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializePointerItem(PointerEvent::PointerItem &item, NetPacket &pck)
{
    int32_t tField {  };
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetPointerId(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetDownTime(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetPressed(static_cast<bool>(tField));
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetGlobalX(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetGlobalY(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetLocalX(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetLocalY(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetWidth(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetHeight(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetPressure(tField);
    CHKR(pck.Read(tField), STREAM_BUF_READ_FAIL, RET_ERR);
    item.SetDeviceId(tField);
    return RET_OK;
}
}
}