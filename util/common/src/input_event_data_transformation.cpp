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
    pkt << key->GetKeyCode() << key->GetKeyAction();
    auto keys = key->GetKeyItems();
    int32_t size = static_cast<int32_t>(keys.size());
    if (size > MAX_KEY_SIZE) {
        MMI_HILOGE("Key exceeds the max range");
        return RET_ERR;
    }
    pkt << size;
    for (const auto &item : keys) {
        pkt << item.GetKeyCode() << item.GetDownTime()
            << item.GetDeviceId() << item.IsPressed() << item.GetUnicode();
    }
    pkt << key->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY)
        << key->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY)
        << key->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write key event failed");
        return RET_ERR;
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
    pkt >> data;
    key->SetKeyCode(data);
    pkt >> data;
    key->SetKeyAction(data);
    int32_t size = 0;
    pkt >> size;
    if (size > MAX_KEY_SIZE) {
        MMI_HILOGE("Key exceeds the max range");
        return RET_ERR;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet read size failed");
        return RET_ERR;
    }
    bool isPressed = false;
    for (int32_t i = 0; i < size; i++) {
        KeyEvent::KeyItem keyItem;
        pkt >> data;
        keyItem.SetKeyCode(data);
        int64_t datatime = 0;
        pkt >> datatime;
        keyItem.SetDownTime(datatime);
        pkt >> data;
        keyItem.SetDeviceId(data);
        pkt >> isPressed;
        if (pkt.ChkRWError()) {
            MMI_HILOGE("Packet read item isPressed failed");
            return RET_ERR;
        }
        keyItem.SetPressed(isPressed);
        uint32_t unicode;
        pkt >> unicode;
        keyItem.SetUnicode(unicode);
        key->AddKeyItem(keyItem);
    }
    bool state = false;
    pkt >> state;
    key->SetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY, state);
    pkt >> state;
    key->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, state);
    pkt >> state;
    key->SetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY, state);
    return RET_OK;
}

int32_t InputEventDataTransformation::SerializeInputEvent(std::shared_ptr<InputEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    pkt << event->GetEventType() << event->GetId() << event->GetActionTime()
        << event->GetAction() << event->GetActionStartTime() << event->GetDeviceId()
        << event->GetTargetDisplayId() << event->GetTargetWindowId()
        << event->GetAgentWindowId() << event->GetFlag();
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Serialize packet is failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializeInputEvent(NetPacket &pkt, std::shared_ptr<InputEvent> event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t tField = 0;
    pkt >> tField;
    pkt >> tField;
    event->SetId(tField);
    int64_t rField = 0;
    pkt >> rField;
    event->SetActionTime(rField);
    pkt >> tField;
    event->SetAction(tField);
    pkt >> rField;
    event->SetActionStartTime(rField);
    pkt >> tField;
    event->SetDeviceId(tField);
    pkt >> tField;
    event->SetTargetDisplayId(tField);
    pkt >> tField;
    event->SetTargetWindowId(tField);
    pkt >> tField;
    event->SetAgentWindowId(tField);
    uint32_t tFlag = InputEvent::EVENT_FLAG_NONE;
    pkt >> tFlag;
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Deserialize packet is failed");
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

    std::vector<int32_t> pointerIds { event->GetPointerIds() };
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
    pkt >> tField;
    event->SetPointerAction(tField);
    pkt >> tField;
    event->SetPointerId(tField);
    pkt >> tField;
    event->SetSourceType(tField);
    pkt >> tField;
    event->SetButtonId(tField);
    uint32_t tAxes;
    pkt >> tAxes;
    double axisValue;
    if (PointerEvent::HasAxis(tAxes, PointerEvent::AXIS_TYPE_SCROLL_VERTICAL)) {
        pkt >> axisValue;
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_VERTICAL, axisValue);
    }
    if (PointerEvent::HasAxis(tAxes, PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL)) {
        pkt >> axisValue;
        event->SetAxisValue(PointerEvent::AXIS_TYPE_SCROLL_HORIZONTAL, axisValue);
    }
    if (PointerEvent::HasAxis(tAxes, PointerEvent::AXIS_TYPE_PINCH)) {
        pkt >> axisValue;
        event->SetAxisValue(PointerEvent::AXIS_TYPE_PINCH, axisValue);
    }

    std::set<int32_t>::size_type nPressed;
    pkt >> nPressed;
    while (nPressed-- > 0) {
        pkt >> tField;
        event->SetButtonPressed(tField);
    }

    std::vector<int32_t>::size_type pointerCnt;
    pkt >> pointerCnt;
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
    pkt >> pressedKeySize;
    while (pressedKeySize-- > 0) {
        pkt >> tField;
        pressedKeys.push_back(tField);
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Unmarshalling pointer event failed");
        return RET_ERR;
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