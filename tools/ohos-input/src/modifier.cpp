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

#include "modifier.h"

#include <cstdint>
#include <set>
#include <sstream>

namespace OHOS::MMI::InputCli {
bool ParseModifiers(const std::string &value, std::vector<int32_t> &modifiers, std::string &error)
{
    if (value.empty()) {
        error = "modifier must not be empty";
        return false;
    }
    if (value.front() == '|' || value.back() == '|') {
        error = "modifier must not start or end with |";
        return false;
    }
    std::stringstream stream(value);
    std::string token;
    std::set<int32_t> seen;
    while (std::getline(stream, token, '|')) {
        if (token.empty()) {
            error = "modifier must not contain empty keys";
            return false;
        }
        int32_t key = 0;
        if (token == "ctrl") {
            key = KEY_CTRL_LEFT;
        } else if (token == "alt") {
            key = KEY_ALT_LEFT;
        } else if (token == "shift") {
            key = KEY_SHIFT_LEFT;
        } else if (token == "meta") {
            key = KEY_META_LEFT;
        } else {
            error = "modifier must use ctrl, alt, shift, or meta";
            return false;
        }
        if (!seen.insert(key).second) {
            error = "modifier must not contain duplicates";
            return false;
        }
        modifiers.push_back(key);
    }
    if (modifiers.empty()) {
        error = "modifier must not be empty";
        return false;
    }
    return true;
}

int32_t PressModifiers(const std::shared_ptr<KeyboardControllerImpl> &keyboard, const std::vector<int32_t> &modifiers)
{
    for (int32_t modifier : modifiers) {
        const int32_t ret = keyboard->PressKey(modifier);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

int32_t ReleaseModifiers(const std::shared_ptr<KeyboardControllerImpl> &keyboard, const std::vector<int32_t> &modifiers)
{
    for (auto modifier = modifiers.rbegin(); modifier != modifiers.rend(); ++modifier) {
        const int32_t ret = keyboard->ReleaseKey(*modifier);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}
} // namespace OHOS::MMI::InputCli
