/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "oh_input_manager.h"

#include "input_manager.h"
#include "mmi_log.h"
#include "oh_key_code.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, OHOS::MMI::MMI_LOG_DOMAIN, "OHInputManager" };
} // namespace

struct Input_KeyState {
    int32_t keyCode;
    int32_t keyState;
    int32_t keySwitch;
};

Input_Result OH_Input_GetKeyState(struct Input_KeyState* keyState)
{
    CALL_DEBUG_ENTER;
    CHKPR(keyState, INPUT_PARAMETER_ERROR);
    if (keyState->keyCode < 0 || keyState->keyCode > KEYCODE_NUMPAD_RIGHT_PAREN) {
        MMI_HILOGE("keyCode is invalid,keyCode:%{public}d", keyState->keyCode);
        return INPUT_PARAMETER_ERROR;
    }
    std::vector<int32_t> pressedKeys;
    std::map<int32_t, int32_t> specialKeysState;
    OHOS::MMI::InputManager::GetInstance()->GetKeyState(pressedKeys, specialKeysState);
    auto iter = std::find(pressedKeys.begin(), pressedKeys.end(), keyState->keyCode);
    if (iter != pressedKeys.end()) {
        keyState->keyState = KEY_PRESSED;
    } else {
        keyState->keyState = KEY_RELEASED;
    }
    auto itr = specialKeysState.find(keyState->keyCode);
    if (itr != specialKeysState.end()) {
        if (itr->second == 0) {
            keyState->keySwitch = KEY_SWITCH_OFF;
        } else {
            keyState->keySwitch = KEY_SWITCH_ON;
        }
    } else {
        keyState->keySwitch = KEY_DEFAULT;
    }
    return INPUT_SUCCESS;
}

struct Input_KeyState* OH_Input_CreateKeyState()
{
    Input_KeyState* keyState = new (std::nothrow) Input_KeyState();
    if (keyState == nullptr) {
        MMI_HILOGE("Memory allocation failed");
    }
    return keyState;
}

void OH_Input_DestroyKeyState(struct Input_KeyState* keyState)
{
    CHKPV(keyState);
    delete keyState;
    keyState = nullptr;
}

void OH_Input_SetKeyCode(struct Input_KeyState* keyState, int32_t keyCode)
{
    CHKPV(keyState);
    if (keyCode < 0 || keyState->keyCode > KEYCODE_NUMPAD_RIGHT_PAREN) {
        MMI_HILOGE("keyCode is invalid,keyCode:%{public}d", keyCode);
        return;
    }
    keyState->keyCode = keyCode;
}

int32_t OH_Input_GetKeyCode(struct Input_KeyState* keyState)
{
    CHKPR(keyState, KEYCODE_UNKNOWN);
    return keyState->keyCode;
}

void OH_Input_SetKeyPressed(struct Input_KeyState* keyState, int32_t keyAction)
{
    CHKPV(keyState);
    keyState->keyState = keyAction;
}

int32_t OH_Input_GetKeyPressed(struct Input_KeyState* keyState)
{
    CHKPR(keyState, KEY_DEFAULT);
    return keyState->keyState;
}

void OH_Input_SetKeySwitch(struct Input_KeyState* keyState, int32_t keySwitch)
{
    CHKPV(keyState);
    keyState->keySwitch = keySwitch;
}

int32_t OH_Input_GetKeySwitch(struct Input_KeyState* keyState)
{
    CHKPR(keyState, KEY_DEFAULT);
    return keyState->keySwitch;
}
