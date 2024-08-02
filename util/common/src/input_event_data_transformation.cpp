/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "input_event_data_transformation.h"

#include "define_multimodal.h"
#include "extra_data.h"
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
#include "sec_comp_enhance_kit.h"
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventDataTransformation"

namespace OHOS {
namespace MMI {
int32_t InputEventDataTransformation::KeyEventToNetPacket(
    const std::shared_ptr<KeyEvent> key, NetPacket &pkt)
{
    if (SerializeInputEvent(key, pkt) != RET_OK) {
        MMI_HILOGE("Serialize input event failed");
        return RET_ERR;
    }
    pkt << key->GetKeyCode() << key->GetKeyAction() << key->GetKeyIntention();
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
    pkt >> data;
    key->SetKeyIntention(data);
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
    ReadFunctionKeys(pkt, key);
    return RET_OK;
}

void InputEventDataTransformation::ReadFunctionKeys(NetPacket &pkt, std::shared_ptr<KeyEvent> key)
{
    CHKPV(key);
    bool state = false;
    pkt >> state;
    key->SetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY, state);
    pkt >> state;
    key->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, state);
    pkt >> state;
    key->SetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY, state);
}

int32_t InputEventDataTransformation::SwitchEventToNetPacket(
    const std::shared_ptr<SwitchEvent> swEvent, NetPacket &pkt)
{
    if (SerializeInputEvent(swEvent, pkt) != RET_OK) {
        MMI_HILOGE("Serialize input event failed");
        return RET_ERR;
    }
    pkt << swEvent->GetSwitchType() << swEvent->GetSwitchValue() << swEvent->GetSwitchMask();
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write key event failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::NetPacketToSwitchEvent(NetPacket &pkt, std::shared_ptr<SwitchEvent> swEvent)
{
    if (DeserializeInputEvent(pkt, swEvent) != RET_OK) {
        MMI_HILOGE("Deserialize input event failed");
        return RET_ERR;
    }
    int32_t data = 0;
    pkt >> data;
    swEvent->SetSwitchType(data);
    pkt >> data;
    swEvent->SetSwitchValue(data);
    pkt >> data;
    swEvent->SetSwitchMask(data);
    return RET_OK;
}

int32_t InputEventDataTransformation::SerializeInputEvent(std::shared_ptr<InputEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    pkt << event->GetEventType() << event->GetId() << event->GetActionTime()
        << event->GetAction() << event->GetActionStartTime() << event->GetSensorInputTime() << event->GetDeviceId()
        << event->GetTargetDisplayId() << event->GetTargetWindowId()
        << event->GetAgentWindowId() << event->GetFlag() << event->IsMarkEnabled();
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
    uint32_t tFlag = InputEvent::EVENT_FLAG_NONE;
    pkt >> tFlag;
    event->AddFlag(tFlag);
    bool markEnabled = true;
    pkt >> markEnabled;
    event->SetMarkEnabled(markEnabled);
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Deserialize packet is failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::Marshalling(std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    if (SerializeInputEvent(event, pkt) != RET_OK) {
        MMI_HILOGE("Serialize input event failed");
        return RET_ERR;
    }
    SerializeFingerprint(event, pkt);
    SerializePointerEvent(event, pkt);
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
    std::vector<uint8_t> buffer = event->GetBuffer();
    if (buffer.size() > ExtraData::MAX_BUFFER_SIZE) {
        MMI_HILOGE("buffer is oversize:%{public}zu", buffer.size());
        return RET_ERR;
    }
    pkt << buffer.size();
    for (const auto &buf : buffer) {
        pkt << buf;
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Marshalling pointer event failed");
        return RET_ERR;
    }
    return RET_OK;
}

void InputEventDataTransformation::SerializePointerEvent(const std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
    pkt << event->GetPointerAction() << event->GetOriginPointerAction() << event->GetPointerId()
        << event->GetSourceType() << event->GetButtonId() << event->GetFingerCount()
        << event->GetZOrder() << event->GetDispatchTimes() << event->GetAxes();
    for (int32_t i = PointerEvent::AXIS_TYPE_UNKNOWN; i < PointerEvent::AXIS_TYPE_MAX; ++i) {
        if (event->HasAxis(static_cast<PointerEvent::AxisType>(i))) {
            pkt << event->GetAxisValue(static_cast<PointerEvent::AxisType>(i));
        }
    }
    pkt << event->GetVelocity();
    pkt << event->GetAxisEventType();
}

void InputEventDataTransformation::SerializeFingerprint(const std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    pkt << event->GetFingerprintDistanceX() << event->GetFingerprintDistanceY();
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
}

int32_t InputEventDataTransformation::DeserializePressedButtons(std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t tField;
    pkt >> tField;
    event->SetPointerAction(tField);
    pkt >> tField;
    event->SetOriginPointerAction(tField);
    pkt >> tField;
    event->SetPointerId(tField);
    pkt >> tField;
    event->SetSourceType(tField);
    pkt >> tField;
    event->SetButtonId(tField);
    pkt >> tField;
    event->SetFingerCount(tField);
    pkt >> tField;
    event->SetZOrder(tField);
    pkt >> tField;
    event->SetDispatchTimes(tField);
    SetAxisInfo(pkt, event);

    std::set<int32_t>::size_type nPressed;
    pkt >> nPressed;
    while (nPressed-- > 0) {
        pkt >> tField;
        event->SetButtonPressed(tField);
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::DeserializePointerIds(std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
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
    return RET_OK;
}

int32_t InputEventDataTransformation::Unmarshalling(NetPacket &pkt, std::shared_ptr<PointerEvent> event)
{
    if (DeserializeInputEvent(pkt, event) != RET_OK) {
        MMI_HILOGE("Deserialize input event failed");
        return RET_ERR;
    }

#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    double distanceX {0.0};
    double distanceY {0.0};
    pkt >> distanceX;
    pkt >> distanceY;
    event->SetFingerprintDistanceX(distanceX);
    event->SetFingerprintDistanceY(distanceY);
#endif // OHOS_BUILD_ENABLE_FINGERPRINT

    if (DeserializePressedButtons(event, pkt) != RET_OK) {
        MMI_HILOGE("Deserialize pressed buttons failed");
        return RET_ERR;
    }

    if (DeserializePointerIds(event, pkt) != RET_OK) {
        MMI_HILOGE("Deserialize pressed ids failed");
        return RET_ERR;
    }

    std::vector<int32_t> pressedKeys;
    std::vector<int32_t>::size_type pressedKeySize;
    int32_t tField;
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

    std::vector<uint8_t> buffer;
    std::vector<uint8_t>::size_type bufferSize;
    pkt >> bufferSize;
    uint8_t buff = 0;
    while (bufferSize-- > 0) {
        pkt >> buff;
        buffer.push_back(buff);
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Unmarshalling pointer event failed");
        return RET_ERR;
    }
    event->SetBuffer(buffer);
    return RET_OK;
}

void InputEventDataTransformation::SetAxisInfo(NetPacket &pkt, std::shared_ptr<PointerEvent> event)
{
    uint32_t tAxes;
    pkt >> tAxes;
    double axisValue;
    for (int32_t i = PointerEvent::AXIS_TYPE_UNKNOWN; i < PointerEvent::AXIS_TYPE_MAX; ++i) {
        if (PointerEvent::HasAxis(tAxes, static_cast<PointerEvent::AxisType>(i))) {
            pkt >> axisValue;
            event->SetAxisValue(static_cast<PointerEvent::AxisType>(i), axisValue);
        }
    }
    double velocity;
    pkt >> velocity;
    event->SetVelocity(velocity);
    int32_t axisEventType;
    pkt >> axisEventType;
    event->SetAxisEventType(axisEventType);
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

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
int32_t InputEventDataTransformation::MarshallingEnhanceData(std::shared_ptr<PointerEvent> event, NetPacket &pkt)
{
    CHKPR(event, ERROR_NULL_POINTER);
    int32_t pointerId = event->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!event->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOGE("Can't find pointer item, pointer:%{public}d", pointerId);
        return RET_ERR;
    }
    SecCompPointEvent *secCompPointEvent = static_cast<SecCompPointEvent*>(malloc(sizeof(SecCompPointEvent)));
    if (secCompPointEvent == NULL) {
        MMI_HILOGE("Malloc failed");
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
        MMI_HILOGE("Marshalling enhanceData failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::UnmarshallingEnhanceData(NetPacket &pkt, std::shared_ptr<PointerEvent> event)
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
        MMI_HILOGE("UnmarshallingEnhanceData pointer event failed");
        return RET_ERR;
    }
    event->SetEnhanceData(enhanceData);
    return RET_OK;
}

struct keyEventEnhanceData {
    int64_t timestamp;
    int32_t keyCode;
};

int32_t InputEventDataTransformation::MarshallingEnhanceData(std::shared_ptr<KeyEvent> event, NetPacket &pkt)
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
        return RET_ERR;
    }
    pkt << enHanceDataLen;
    std::vector<uint8_t> realBuf;
    for (size_t i = 0; i < enHanceDataLen; i++) {
        realBuf.push_back(enHanceData[i]);
        pkt << realBuf[i];
    }
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Marshalling enhanceData failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t InputEventDataTransformation::UnmarshallingEnhanceData(NetPacket &pkt, std::shared_ptr<KeyEvent> event)
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
        MMI_HILOGE("UnmarshallingEnhanceData key event failed");
        return RET_ERR;
    }
    event->SetEnhanceData(enhanceData);
    return RET_OK;
}
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
} // namespace MMI
} // namespace OHOS
