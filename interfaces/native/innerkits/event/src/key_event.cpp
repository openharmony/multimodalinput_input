/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "key_event.h"

#include <memory>
namespace OHOS {
void KeyEvent::Initialize(MultimodalProperty &multimodalProperty, KeyProperty &keyProperty)
{
    MultimodalEvent::Initialize(multimodalProperty);
    keyProperty_.isPressed = keyProperty.isPressed;
    keyProperty_.keyCode = keyProperty.keyCode;
    keyProperty_.keyDownDuration = keyProperty.keyDownDuration;
}

int KeyEvent::GetMaxKeyCode()
{
    return NOW_MAX_CODE;
}

bool KeyEvent::IsKeyDown()
{
    return keyProperty_.isPressed;
}

int KeyEvent::GetKeyCode()
{
    return keyProperty_.keyCode;
}

int KeyEvent::GetKeyDownDuration()
{
    return keyProperty_.keyDownDuration;
}

bool KeyEvent::Marshalling(Parcel &parcel) const
{
    bool result = parcel.WriteInt32(multiProperty_.highLevelEvent);
    if (!result) {
        return result;
    }
    result = parcel.WriteString(multiProperty_.uuid);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(multiProperty_.sourceType);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(multiProperty_.occurredTime);
    if (!result) {
        return result;
    }
    result = parcel.WriteString(multiProperty_.deviceId);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(multiProperty_.inputDeviceId);
    if (!result) {
        return result;
    }
    result = parcel.WriteBool(multiProperty_.isHighLevelEvent);
    if (!result) {
        return result;
    }

    result = parcel.WriteBool(keyProperty_.isPressed);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(keyProperty_.keyCode);
    if (!result) {
        return result;
    }
    result = parcel.WriteInt32(keyProperty_.keyDownDuration);
    if (!result) {
        return result;
    }

    return result;
}

KeyEvent *KeyEvent::Unmarshalling(Parcel &parcel)
{
    KeyProperty property;
    MultimodalProperty multiProperty;

    multiProperty.highLevelEvent = parcel.ReadInt32();
    multiProperty.uuid = parcel.ReadString();
    multiProperty.sourceType = parcel.ReadInt32();
    multiProperty.occurredTime = parcel.ReadInt32();
    multiProperty.deviceId = parcel.ReadString();
    multiProperty.inputDeviceId = parcel.ReadInt32();
    multiProperty.isHighLevelEvent = parcel.ReadBool();
    property.isPressed = parcel.ReadBool();
    property.keyCode = parcel.ReadInt32();
    property.keyDownDuration = parcel.ReadInt32();
    KeyEvent *event = new (std::nothrow) KeyEvent();
    if (event == nullptr) {
        return nullptr;
    }
    event->Initialize(multiProperty, property);
    return event;
}
}
