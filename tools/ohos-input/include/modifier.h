/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_INPUT_MODIFIER_H
#define OHOS_INPUT_MODIFIER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "keyboard_controller_impl.h"

namespace OHOS::MMI::InputCli {
constexpr int32_t KEY_ALT_LEFT = 2045;
constexpr int32_t KEY_SHIFT_LEFT = 2047;
constexpr int32_t KEY_CTRL_LEFT = 2072;
constexpr int32_t KEY_META_LEFT = 2076;

bool ParseModifiers(const std::string &value, std::vector<int32_t> &modifiers, std::string &error);

int32_t PressModifiers(const std::shared_ptr<KeyboardControllerImpl> &keyboard, const std::vector<int32_t> &modifiers);
int32_t ReleaseModifiers(const std::shared_ptr<KeyboardControllerImpl> &keyboard,
    const std::vector<int32_t> &modifiers);
} // namespace OHOS::MMI::InputCli

#endif
