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

#ifndef KEY_EVENT_VALUE_TRANSFORMATION_H
#define KEY_EVENT_VALUE_TRANSFORMATION_H

#include <string>
#include <map>
#include <iostream>
#include <xkbcommon/xkbcommon.h>
#include "hos_key_event.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
enum MMI_SYSTEM_KEY_STATE {
    MMI_NO_SYSTEM_KEY = 0,
    MMI_SYSTEM_KEY = 1,
};

struct KeyEventValueTransformations {
    std::string keyEvent;
    int16_t keyValueOfNative;
    int16_t keyValueOfHos;
    int16_t keyEventOfHos;
    int16_t isSystemKey;
};

KeyEventValueTransformations KeyValueTransformationByInput(int16_t keyValueOfInput);

class KeyEventValueTransformation {
public:
    KeyEventValueTransformation();
    DISALLOW_COPY_AND_MOVE(KeyEventValueTransformation);
    virtual ~KeyEventValueTransformation();

    bool Init();
    uint32_t KeyboardHandleKeySym(uint32_t keyboardKey);

private:
    xkb_state *state_ = nullptr;
};
} // namespace MMI
} // namespace OHOS

#endif // KEY_EVENT_VALUE_TRANSFORMATION_H