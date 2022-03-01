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

#include "send_message.h"
#include "proto.h"
#include "sys/file.h"

using namespace std;
using namespace OHOS::MMI;

namespace {
[[maybe_unused]] static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "SendMessage"};
}

int32_t SendMessage::GetDevIndexName(const std::string& deviceName)
{
    static const std::map<std::string, INPUT_DEVICE_INDEX> deviceTypeToIndexMap = {
        {"keyboard model1", INPUT_DEVICE_KEYBOARD_INDEX},
        {"keyboard model2", INPUT_DEVICE_KEYBOARD_INDEX},
        {"keyboard model3", INPUT_DEVICE_KEYBOARD_INDEX},
        {"mouse", INPUT_DEVICE_POINTER_INDEX},
        {"trackball", INPUT_DEVICE_POINTER_INDEX},
        {"touch", INPUT_DEVICE_TOUCH_INDEX},
        {"pen", INPUT_DEVICE_TABLET_TOOL_INDEX},
        {"pad", INPUT_DEVICE_TABLET_PAD_INDEX},
        {"joystick", INPUT_DEVICE_JOYSTICK_INDEX},
        {"gamePad", INPUT_DEVICE_GAMEPAD_INDEX},
        {"finger", INPUT_DEVICE_FINGER_INDEX},
        {"knob model1", INPUT_DEVICE_SWITCH_INDEX},
        {"knob model2", INPUT_DEVICE_SWITCH_INDEX},
        {"knob model3", INPUT_DEVICE_SWITCH_INDEX},
        {"remoteControl", INPUT_DEVICE_REMOTE_CONTROL},
        {"trackpad model1", INPUT_DEVICE_TRACKPAD5_INDEX},
        {"trackpad model2", INPUT_DEVICE_TRACKPAD5_INDEX},
    };

    auto iter = deviceTypeToIndexMap.find(deviceName);
    if (iter == deviceTypeToIndexMap.end()) {
        return RET_ERR;
    }
    return static_cast<int32_t>(iter->second);
}
