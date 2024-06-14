/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "key_unicode_transformation.h"

#include <map>

#include "hos_key_event.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyUnicodeTransformation"

namespace OHOS {
namespace MMI {
namespace {
struct KeyUnicode {
    uint32_t original { 0 };
    uint32_t transitioned { 0 };
};

constexpr uint32_t DEFAULT_UNICODE = 0x0000;

const std::map<int32_t, KeyUnicode> KEY_UNICODE_TRANSFORMATION = {
    { HOS_KEY_A,                { 0x0061, 0x0041 } },
    { HOS_KEY_B,                { 0x0062, 0x0042 } },
    { HOS_KEY_C,                { 0x0063, 0x0043 } },
    { HOS_KEY_D,                { 0x0064, 0x0044 } },
    { HOS_KEY_E,                { 0x0065, 0x0045 } },
    { HOS_KEY_F,                { 0x0066, 0x0046 } },
    { HOS_KEY_G,                { 0x0067, 0x0047 } },
    { HOS_KEY_H,                { 0x0068, 0x0048 } },
    { HOS_KEY_I,                { 0x0069, 0x0049 } },
    { HOS_KEY_J,                { 0x006A, 0x004A } },
    { HOS_KEY_K,                { 0x006B, 0x004B } },
    { HOS_KEY_L,                { 0x006C, 0x004C } },
    { HOS_KEY_M,                { 0x006D, 0x004D } },
    { HOS_KEY_N,                { 0x006E, 0x004E } },
    { HOS_KEY_O,                { 0x006F, 0x004F } },
    { HOS_KEY_P,                { 0x0070, 0x0050 } },
    { HOS_KEY_Q,                { 0x0071, 0x0051 } },
    { HOS_KEY_R,                { 0x0072, 0x0052 } },
    { HOS_KEY_S,                { 0x0073, 0x0053 } },
    { HOS_KEY_T,                { 0x0074, 0x0054 } },
    { HOS_KEY_U,                { 0x0075, 0x0055 } },
    { HOS_KEY_V,                { 0x0076, 0x0056 } },
    { HOS_KEY_W,                { 0x0077, 0x0057 } },
    { HOS_KEY_X,                { 0x0078, 0x0058 } },
    { HOS_KEY_Y,                { 0x0079, 0x0059 } },
    { HOS_KEY_Z,                { 0x007A, 0x005A } },
    { HOS_KEY_0,                { 0x0030, 0x0029 } },
    { HOS_KEY_1,                { 0x0031, 0x0021 } },
    { HOS_KEY_2,                { 0x0032, 0x0040 } },
    { HOS_KEY_3,                { 0x0033, 0x0023 } },
    { HOS_KEY_4,                { 0x0034, 0x0024 } },
    { HOS_KEY_5,                { 0x0035, 0x0025 } },
    { HOS_KEY_6,                { 0x0036, 0x005E } },
    { HOS_KEY_7,                { 0x0037, 0x0026 } },
    { HOS_KEY_8,                { 0x0038, 0x002A } },
    { HOS_KEY_9,                { 0x0039, 0x0028 } },
    { HOS_KEY_GRAVE,            { 0x0060, 0x007E } },
    { HOS_KEY_MINUS,            { 0x002D, 0x005F } },
    { HOS_KEY_EQUALS,           { 0x002B, 0x003D } },
    { HOS_KEY_LEFT_BRACKET,     { 0x005B, 0x007B } },
    { HOS_KEY_RIGHT_BRACKET,    { 0x005D, 0x007D } },
    { HOS_KEY_BACKSLASH,        { 0x005C, 0x007C } },
    { HOS_KEY_SEMICOLON,        { 0x003B, 0x003A } },
    { HOS_KEY_APOSTROPHE,       { 0x0027, 0x0022 } },
    { HOS_KEY_SLASH,            { 0x002F, 0x003F } },
    { HOS_KEY_COMMA,            { 0x002C, 0x003C } },
    { HOS_KEY_PERIOD,           { 0x002E, 0x003E } },
    { HOS_KEY_NUMPAD_0,         { 0x0030, 0x0000 } },
    { HOS_KEY_NUMPAD_1,         { 0x0031, 0x0000 } },
    { HOS_KEY_NUMPAD_2,         { 0x0032, 0x0000 } },
    { HOS_KEY_NUMPAD_3,         { 0x0033, 0x0000 } },
    { HOS_KEY_NUMPAD_4,         { 0x0034, 0x0000 } },
    { HOS_KEY_NUMPAD_5,         { 0x0035, 0x0000 } },
    { HOS_KEY_NUMPAD_6,         { 0x0036, 0x0000 } },
    { HOS_KEY_NUMPAD_7,         { 0x0037, 0x0000 } },
    { HOS_KEY_NUMPAD_8,         { 0x0038, 0x0000 } },
    { HOS_KEY_NUMPAD_9,         { 0x0039, 0x0000 } },
    { HOS_KEY_NUMPAD_DIVIDE,    { 0x002F, 0x0000 } },
    { HOS_KEY_NUMPAD_MULTIPLY,  { 0x0038, 0x0000 } },
    { HOS_KEY_NUMPAD_SUBTRACT,  { 0x002D, 0x0000 } },
    { HOS_KEY_NUMPAD_ADD,       { 0x002B, 0x0000 } },
    { HOS_KEY_NUMPAD_DOT,       { 0x002E, 0x0000 } }
};
} // namespace

bool IsShiftPressed(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPF(keyEvent);
    auto pressedKeys = keyEvent->GetPressedKeys();
    for (auto iter = pressedKeys.cbegin(); iter != pressedKeys.cend(); ++iter) {
        if ((*iter == HOS_KEY_SHIFT_LEFT) || (*iter == HOS_KEY_SHIFT_RIGHT)) {
            return true;
        }
    }
    return false;
}

uint32_t KeyCodeToUnicode(int32_t keyCode, std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPR(keyEvent, DEFAULT_UNICODE);
    auto iter = KEY_UNICODE_TRANSFORMATION.find(keyCode);
    if (iter == KEY_UNICODE_TRANSFORMATION.end()) {
        return DEFAULT_UNICODE;
    }
    const KeyUnicode &keyUnicode = iter->second;
    bool isCapsEnable = keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY);
    bool isShiftPress = IsShiftPressed(keyEvent);
    if (keyCode >= HOS_KEY_A && keyCode <= HOS_KEY_Z) {
        if (isShiftPress) {
            isCapsEnable = !isCapsEnable;
        }
        if (isCapsEnable) {
            return keyUnicode.transitioned;
        }
    } else {
        if (isShiftPress) {
            return keyUnicode.transitioned;
        }
    }
    return keyUnicode.original;
}
} // namespace MMI
} // namespace OHOS