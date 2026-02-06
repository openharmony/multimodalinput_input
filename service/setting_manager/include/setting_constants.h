/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#pragma once
#include <string>
#include <vector>

namespace OHOS {
namespace MMI {
namespace SettingConstants {
    // Version numbers
    extern const std::string VERSION_NUMBERS_LATEST;
    extern const std::string VERSION_NUMBERS_INITIAL;
    extern const std::string FIELD_VERSION;

    // Default values
    constexpr int32_t DEFAULT_USER_ID = 100;
    constexpr int32_t MAX_USER_ID = 10000;

    // File paths (internal use only)
    extern const std::string GLOBAL_CONFIG_PATH;
    extern const std::string GLOBAL_MOUSE_FILE_PATH;
    extern const std::string GLOBAL_KEYBOARD_FILE_PATH;
    extern const std::string GLOBAL_TOUCHPAD_FILE_PATH;

    // Field type sets for migration
    extern const std::vector<std::string> SETTING_FIELDS_BOOL;
    extern const std::vector<std::string> SETTING_FIELDS_NUM;
}  // namespace SettingConstants
}  // namespace MMI
}  // namespace OHOS
