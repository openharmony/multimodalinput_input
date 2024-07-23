/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "input_event_transmission/input_event_serialization.h"

#include "extra_data.h"
#ifdef OHOS_BUILD_ENABLE_SECURITY_PART
#include "sec_comp_enhance_kit.h"
#endif // OHOS_BUILD_ENABLE_SECURITY_PART

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "InputEventSerialization"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
namespace {
constexpr int32_t MAX_KEY_SIZE { 395 };
} // namespace

int32_t InputEventSerialization::KeyEventToNetPacket(
    const std::shared_ptr<MMI::KeyEvent> key, NetPacket &pkt)
{
    if (SerializeInputEvent(key, pkt) != RET_OK) {
        FI_HILOGE("Serialize input event failed");
        return RET_ERR;
    }
    pkt << key->GetKeyCode() << key->GetKeyAction() << key->GetKeyIntention();
    auto keys = key->GetKeyItems();
    int32_t size = static_cast<int32_t>(keys.size());
    if (size > MAX_KEY_SIZE) {
        FI_HILOGE("Key exceeds the max range");
        return RET_ERR;
    }
    pkt << size;
    for (const auto &item : keys) {
        pkt << item.GetKeyCode() << item.GetDownTime()
            << item.GetDeviceId() << item.IsPressed() << item.GetUnicode();
    }
    pkt << key->GetFunctionKey(MMI::KeyEvent::NUM_LOCK_FUNCTION_KEY)
        << key->GetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY)
        << key->GetFunctionKey(MMI::KeyEvent::SCROLL_LOCK_FUNCTION_KEY);
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write key event failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::NetPacketToKeyEvent(NetPacket &pkt, std::shared_ptr<MMI::KeyEvent> key)
{
    if (DeserializeInputEvent(pkt, key) != RET_OK) {
        FI_HILOGE("Deserialize input event failed");
        return RET_ERR;
    }
    int32_t data = 0;
    pkt >> data;
    key->SetKeyCode(data);
    pkt >> data;
    key->SetKeyAction(data);
    pkt >> data;
    key->SetKeyIntention(data);
    int32_t size = 0;
    pkt >> size;
    if (size > MAX_KEY_SIZE) {
        FI_HILOGE("Key exceeds the max range");
        return RET_ERR;
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet read size failed");
        return RET_ERR;
    }
    bool isPressed = false;
    for (int32_t i = 0; i < size; i++) {
        MMI::KeyEvent::KeyItem keyItem;
        pkt >> data;
        keyItem.SetKeyCode(data);
        int64_t datatime = 0;
        pkt >> datatime;
        keyItem.SetDownTime(datatime);
        pkt >> data;
        keyItem.SetDeviceId(data);
        pkt >> isPressed;
        if (pkt.ChkRWError()) {
            FI_HILOGE("Packet read item isPressed failed");
            return RET_ERR;
        }
        keyItem.SetPressed(isPressed);
        uint32_t unicode;
        pkt >> unicode;
        keyItem.SetUnicode(unicode);
        key->AddKeyItem(keyItem);
    }
    ReadFunctionKeys(pkt, key);
    return RET_OK;
}

void InputEventSerialization::ReadFunctionKeys(NetPacket &pkt, std::shared_ptr<MMI::KeyEvent> key)
{
    CHKPV(key);
    bool state = false;
    pkt >> state;
    key->SetFunctionKey(MMI::KeyEvent::NUM_LOCK_FUNCTION_KEY, state);
    pkt >> state;
    key->SetFunctionKey(MMI::KeyEvent::CAPS_LOCK_FUNCTION_KEY, state);
    pkt >> state;
    key->SetFunctionKey(MMI::KeyEvent::SCROLL_LOCK_FUNCTION_KEY, state);
}

int32_t InputEventSerialization::SwitchEventToNetPacket(
    const std::shared_ptr<MMI::SwitchEvent> swEvent, NetPacket &pkt)
{
    if (SerializeInputEvent(swEvent, pkt) != RET_OK) {
        FI_HILOGE("Serialize input event failed");
        return RET_ERR;
    }
    pkt << swEvent->GetSwitchValue() << swEvent->GetSwitchMask();
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write key event failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::NetPacketToSwitchEvent(NetPacket &pkt, std::shared_ptr<MMI::SwitchEvent> swEvent)
{
    if (DeserializeInputEvent(pkt, swEvent) != RET_OK) {
        FI_HILOGE("Deserialize input event failed");
        return RET_ERR;
    }
    int32_t data = 0;
    pkt >> data;
    swEvent->SetSwitchValue(data);
    pkt >> data;
    swEvent->SetSwitchMask(data);
    return RET_OK;
}

int32_t InputEventSerialization::SerializeInputEvent(std::shared_ptr<MMI::InputEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    pkt << event->GetEventType() << event->GetId() << event->GetActionTime()
        << event->GetAction() << event->GetActionStartTime() << event->GetSensorInputTime() << event->GetDeviceId()
        << event->GetTargetDisplayId() << event->GetTargetWindowId()
        << event->GetAgentWindowId() << event->GetFlag();
    if (pkt.ChkRWError()) {
        FI_HILOGE("Serialize packet is failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::DeserializeInputEvent(NetPacket &pkt, std::shared_ptr<MMI::InputEvent> event)
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
    uint64_t sensorTime;
    pkt >> sensorTime;
    event->SetSensorInputTime(sensorTime);
    pkt >> tField;
    event->SetDeviceId(tField);
    pkt >> tField;
    event->SetTargetDisplayId(tField);
    pkt >> tField;
    event->SetTargetWindowId(tField);
    pkt >> tField;
    event->SetAgentWindowId(tField);
    uint32_t tFlag = MMI::InputEvent::EVENT_FLAG_NONE;
    pkt >> tFlag;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Deserialize packet is failed");
        return RET_ERR;
    }
    event->AddFlag(tFlag);
    return RET_OK;
}

int32_t InputEventSerialization::SerializeBaseInfo(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt)
{
    int32_t pointerAction = event->GetPointerAction();
    int32_t pointerId = event->GetPointerId();
    int32_t sourceType = event->GetSourceType();
    int32_t btnId = event->GetButtonId();
    int32_t fingerCnt = event->GetFingerCount();
    float zOrder = event->GetZOrder();

    pkt << pointerAction << pointerId << sourceType << btnId << fingerCnt << zOrder;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to serialize base information of pointer event");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::DeserializeBaseInfo(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event)
{
    int32_t pointerAction {};
    int32_t pointerId {};
    int32_t sourceType {};
    int32_t btnId {};
    int32_t fingerCnt {};
    float zOrder {};

    pkt >> pointerAction >> pointerId >> sourceType >> btnId >> fingerCnt >> zOrder;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to deserialize base information of pointer event");
        return RET_ERR;
    }
    event->SetPointerAction(pointerAction);
    event->SetPointerId(pointerId);
    event->SetSourceType(sourceType);
    event->SetButtonId(btnId);
    event->SetFingerCount(fingerCnt);
    event->SetZOrder(zOrder);
    return RET_OK;
}

int32_t InputEventSerialization::SerializeAxes(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt)
{
    uint32_t axes = event->GetAxes();
    pkt << axes;

    for (int32_t i = MMI::PointerEvent::AXIS_TYPE_UNKNOWN; i < MMI::PointerEvent::AXIS_TYPE_MAX; ++i) {
        if (event->HasAxis(static_cast<MMI::PointerEvent::AxisType>(i))) {
            double axisValue = event->GetAxisValue(static_cast<MMI::PointerEvent::AxisType>(i));
            pkt << axisValue;
        }
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to serialize axes");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::DeserializeAxes(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event)
{
    uint32_t axes {};
    double axisValue {};

    pkt >> axes;

    for (int32_t i = MMI::PointerEvent::AXIS_TYPE_UNKNOWN; i < MMI::PointerEvent::AXIS_TYPE_MAX; ++i) {
        if (MMI::PointerEvent::HasAxis(axes, static_cast<MMI::PointerEvent::AxisType>(i))) {
            pkt >> axisValue;
            event->SetAxisValue(static_cast<MMI::PointerEvent::AxisType>(i), axisValue);
        }
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to deserialize axes");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::SerializePressedButtons(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt)
{
    std::set<int32_t> pressedBtns = event->GetPressedButtons();
    std::set<int32_t>::size_type nPressed = pressedBtns.size();

    pkt << nPressed;

    for (int32_t btnId : pressedBtns) {
        pkt << btnId;
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to serialize pressed buttons");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::DeserializePressedButtons(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event)
{
    std::set<int32_t>::size_type nPressed;
    int32_t btnId {};

    pkt >> nPressed;

    for (; nPressed > 0; --nPressed) {
        pkt >> btnId;
        event->SetButtonPressed(btnId);
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to deserialize pressed buttons");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::SerializePointerItem(NetPacket &pkt, MMI::PointerEvent::PointerItem &item)
{
    pkt << item;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to serialize pointer item");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::DeserializePointerItem(NetPacket &pkt, MMI::PointerEvent::PointerItem &item)
{
    pkt >> item;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to deserialize pointer item");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::SerializePointers(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt)
{
    std::vector<int32_t> pointerIds = event->GetPointerIds();
    std::vector<int32_t>::size_type nPointers = pointerIds.size();

    pkt << nPointers;

    for (const auto &pointerId : pointerIds) {
        MMI::PointerEvent::PointerItem item;

        if (!event->GetPointerItem(pointerId, item)) {
            FI_HILOGE("Get pointer item failed");
            return RET_ERR;
        }
        if (SerializePointerItem(pkt, item) != RET_OK) {
            FI_HILOGE("Failed to serialize one pointer item");
            return RET_ERR;
        }
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to serialize pointers");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::DeserializePointers(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event)
{
    std::vector<int32_t>::size_type nPointers;
    pkt >> nPointers;

    for (; nPointers > 0; --nPointers) {
        MMI::PointerEvent::PointerItem item;

        if (DeserializePointerItem(pkt, item) != RET_OK) {
            FI_HILOGE("Failed to deserialize one pointer item");
            return RET_ERR;
        }
        event->AddPointerItem(item);
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to deserialize pointers");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::SerializePressedKeys(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt)
{
    std::vector<int32_t> pressedKeys = event->GetPressedKeys();
    std::vector<int32_t>::size_type nPressed = pressedKeys.size();

    pkt << nPressed;

    for (std::vector<int32_t>::size_type i = 0; i < nPressed; ++i) {
        int32_t keyCode = pressedKeys[i];
        pkt << keyCode;
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to serialize pressed keys");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::DeserializePressedKeys(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event)
{
    std::vector<int32_t>::size_type nPressed {};
    pkt >> nPressed;

    std::vector<int32_t> pressedKeys;
    int32_t keyCode {};

    for (; nPressed > 0; --nPressed) {
        pkt >> keyCode;
        pressedKeys.push_back(keyCode);
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to deserialize pressed keys");
        return RET_ERR;
    }
    event->SetPressedKeys(pressedKeys);
    return RET_OK;
}

int32_t InputEventSerialization::SerializeBuffer(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt)
{
    std::vector<uint8_t> buffer = event->GetBuffer();
    if (buffer.size() > MMI::ExtraData::MAX_BUFFER_SIZE) {
        FI_HILOGE("buffer is oversize:%{public}zu", buffer.size());
        return RET_ERR;
    }
    std::vector<uint8_t>::size_type bufSize = buffer.size();
    pkt << bufSize;

    for (std::vector<uint8_t>::size_type i = 0; i < bufSize; ++i) {
        uint8_t item = buffer[i];
        pkt << item;
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to serialize buffer");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::DeserializeBuffer(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event)
{
    std::vector<uint8_t>::size_type bufSize {};
    pkt >> bufSize;

    std::vector<uint8_t> buffer;
    uint8_t item {};

    for (; bufSize > 0; --bufSize) {
        pkt >> item;
        buffer.push_back(item);
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Failed to deserialize buffer");
        return RET_ERR;
    }
    event->SetBuffer(buffer);
    return RET_OK;
}

int32_t InputEventSerialization::Marshalling(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);

    if (SerializeInputEvent(event, pkt) != RET_OK) {
        FI_HILOGE("Serialize input event failed");
        return RET_ERR;
    }
    if (SerializeBaseInfo(event, pkt) != RET_OK) {
        FI_HILOGE("Failed to serialize base information of pointer event");
        return RET_ERR;
    }
    if (SerializeAxes(event, pkt) != RET_OK) {
        FI_HILOGE("Failed to serialize axes");
        return RET_ERR;
    }
    if (SerializePressedButtons(event, pkt) != RET_OK) {
        FI_HILOGE("Failed to serialize pressed buttons");
        return RET_ERR;
    }
    if (SerializePointers(event, pkt) != RET_OK) {
        FI_HILOGE("Failed to serialize pointers");
        return RET_ERR;
    }
    if (SerializePressedKeys(event, pkt) != RET_OK) {
        FI_HILOGE("Failed to serialize pressed keys");
        return RET_ERR;
    }
    if (SerializeBuffer(event, pkt) != RET_OK) {
        FI_HILOGE("Failed to serialize buffer");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::Unmarshalling(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, ERROR_NULL_POINTER);

    if (DeserializeInputEvent(pkt, event) != RET_OK) {
        FI_HILOGE("Failed to deserialize input event");
        return RET_ERR;
    }
    if (DeserializeBaseInfo(pkt, event) != RET_OK) {
        FI_HILOGE("Failed to deserialize base information of pointer event");
        return RET_ERR;
    }
    if (DeserializeAxes(pkt, event) != RET_OK) {
        FI_HILOGE("Failed to deserialize axes");
        return RET_ERR;
    }
    if (DeserializePressedButtons(pkt, event) != RET_OK) {
        FI_HILOGE("Failed to deserialize pressed buttons");
        return RET_ERR;
    }
    if (DeserializePointers(pkt, event) != RET_OK) {
        FI_HILOGE("Failed to deserialize pointers");
        return RET_ERR;
    }
    if (DeserializePressedKeys(pkt, event) != RET_OK) {
        FI_HILOGE("Failed to deserialize pressed keys");
        return RET_ERR;
    }
    if (DeserializeBuffer(pkt, event) != RET_OK) {
        FI_HILOGE("Failed to deserialize buffer");
        return RET_ERR;
    }
    return RET_OK;
}

#ifdef OHOS_BUILD_ENABLE_SECURITY_PART
int32_t InputEventSerialization::MarshallingEnhanceData(std::shared_ptr<MMI::PointerEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t pointerId = event->GetPointerId();
    MMI::PointerEvent::PointerItem pointerItem;
    if (!event->GetPointerItem(pointerId, pointerItem)) {
        FI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    SecCompPointEvent *secCompPointEvent = static_cast<SecCompPointEvent*>(malloc(sizeof(SecCompPointEvent)));
    if (secCompPointEvent == NULL) {
        FI_HILOGE("Malloc failed");
        return RET_ERR;
    }
    secCompPointEvent->touchX = pointerItem.GetDisplayX();
    secCompPointEvent->touchY = pointerItem.GetDisplayY();
    secCompPointEvent->timeStamp = event->GetActionTime();
    uint32_t dataLen = sizeof(*secCompPointEvent);
    uint8_t outBuf[MAX_HMAC_SIZE] = { 0 };
    uint8_t* enHanceData = reinterpret_cast<uint8_t *>(&outBuf[0]);
    uint32_t enHanceDataLen = MAX_HMAC_SIZE;
    int32_t result = Security::SecurityComponent::SecCompEnhanceKit::GetPointerEventEnhanceData(secCompPointEvent,
        dataLen, enHanceData, enHanceDataLen);
    if (result != 0 || enHanceDataLen > MAX_HMAC_SIZE) {
        pkt << 0;
        free(secCompPointEvent);
        secCompPointEvent = nullptr;
        FI_HILOGD("GetPointerEventEnhanceData failed!");
        return RET_ERR;
    }
    pkt << enHanceDataLen;
    std::vector<uint8_t> realBuf;
    for (size_t i = 0; i < enHanceDataLen; i++) {
        realBuf.push_back(enHanceData[i]);
        pkt << realBuf[i];
    }
    free(secCompPointEvent);
    secCompPointEvent = nullptr;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Marshalling enhanceData failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::UnmarshallingEnhanceData(NetPacket &pkt, std::shared_ptr<MMI::PointerEvent> event)
{
    uint32_t enHanceDataLen;
    pkt >> enHanceDataLen;
    if (enHanceDataLen == 0) {
        return RET_OK;
    }
    uint8_t enhanceDataBuf[enHanceDataLen];
    std::vector<uint8_t> enhanceData;
    for (size_t i = 0; i < enHanceDataLen; i++) {
        pkt >> enhanceDataBuf[i];
        enhanceData.push_back(enhanceDataBuf[i]);
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("UnmarshallingEnhanceData pointer event failed");
        return RET_ERR;
    }
    event->SetEnhanceData(enhanceData);
    return RET_OK;
}

struct keyEventEnhanceData {
    int64_t timestamp;
    int32_t keyCode;
};

int32_t InputEventSerialization::MarshallingEnhanceData(std::shared_ptr<MMI::KeyEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    struct keyEventEnhanceData secCompKeyEvent;
    secCompKeyEvent.timestamp = event->GetActionTime();
    secCompKeyEvent.keyCode = event->GetKeyCode();
    uint32_t dataLen = sizeof(secCompKeyEvent);
    uint8_t outBuf[MAX_HMAC_SIZE] = { 0 };
    uint8_t* enHanceData = reinterpret_cast<uint8_t *>(&outBuf[0]);
    uint32_t enHanceDataLen = MAX_HMAC_SIZE;
    int32_t result = Security::SecurityComponent::SecCompEnhanceKit::GetPointerEventEnhanceData(&secCompKeyEvent,
        dataLen, enHanceData, enHanceDataLen);
    if (result != 0 || enHanceDataLen > MAX_HMAC_SIZE) {
        pkt << 0;
        FI_HILOGD("GetKeyEventEnhanceData failed!");
        return RET_ERR;
    }
    pkt << enHanceDataLen;
    std::vector<uint8_t> realBuf;
    for (size_t i = 0; i < enHanceDataLen; i++) {
        realBuf.push_back(enHanceData[i]);
        pkt << realBuf[i];
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("Marshalling enhanceData failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventSerialization::UnmarshallingEnhanceData(NetPacket &pkt, std::shared_ptr<MMI::KeyEvent> event)
{
    uint32_t enHanceDataLen;
    pkt >> enHanceDataLen;
    if (enHanceDataLen == 0 || enHanceDataLen > MAX_HMAC_SIZE) {
        return RET_OK;
    }
    uint8_t enhanceDataBuf[enHanceDataLen];
    std::vector<uint8_t> enhanceData;
    for (size_t i = 0; i < enHanceDataLen; i++) {
        pkt >> enhanceDataBuf[i];
        enhanceData.push_back(enhanceDataBuf[i]);
    }
    if (pkt.ChkRWError()) {
        FI_HILOGE("UnmarshallingEnhanceData key event failed");
        return RET_ERR;
    }
    event->SetEnhanceData(enhanceData);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_SECURITY_PART
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
