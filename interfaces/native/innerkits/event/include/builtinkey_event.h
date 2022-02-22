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
#ifndef BUILTINKEY_EVENT_H
#define BUILTINKEY_EVENT_H

#include "key_event_pre.h"
#include "nocopyable.h"

namespace OHOS {
/**
 * Defines the key events of internal input devices.
 *
 * <p>Key events of all internal input devices, such as buttons on the TV, and vehicle, and knobs,
 * are all defined by this class. The OS manages key events of internal input devices in a unified
 * manner. Permissions have been granted for keycodes defined in this class and its child classes.
 * This means that access to key events requires the respective permissions.
 *
 * @see KeyEvent
 * @since 1
 */
class BuiltinKeyEvent : public KeyEvent {
public:
    BuiltinKeyEvent() = default;
    DISALLOW_COPY_AND_MOVE(BuiltinKeyEvent);
    virtual ~BuiltinKeyEvent();
};
} // namespace OHOS
#endif // BUILTINKEY_EVENT_H