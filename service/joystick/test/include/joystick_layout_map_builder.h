/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef JOYSTICK_LAYOUT_MAP_BUILDER_H
#define JOYSTICK_LAYOUT_MAP_BUILDER_H

#include <map>

#include "cJSON.h"
#include "nocopyable.h"

#include "joystick_layout_map.h"

namespace OHOS {
namespace MMI {
class JoystickLayoutMapBuilder final {
public:
    static void BuildJoystickLayoutMap(const JoystickLayoutMap &layout, const std::string &outputFile);

private:
    static std::string MapKeyName(int32_t keyCode);
    static void SerializeJoystickLayoutMap(cJSON *jsonConfig, const std::string &outputFile);
    static void WriteKeys(cJSON *jsonDoc, const std::unordered_map<int32_t, JoystickLayoutMap::Key> &keys);
    static void WriteKeyInfo(cJSON *jsonKeys, int32_t rawCode, const JoystickLayoutMap::Key &keyInfo);
    static void WriteAxes(cJSON *jsonDoc, const std::unordered_map<int32_t, JoystickLayoutMap::AxisInfo> &axes);
    static void WriteAxisInfo(cJSON *jsonAxes, int32_t rawCode, const JoystickLayoutMap::AxisInfo &axisInfo);
    static bool WriteAxisMode(cJSON *jsonAxis, const JoystickLayoutMap::AxisInfo &axisInfo);

    JoystickLayoutMapBuilder() = default;
    ~JoystickLayoutMapBuilder() = default;
    DISALLOW_COPY_AND_MOVE(JoystickLayoutMapBuilder);

    static std::unordered_map<int32_t, std::string> keyNames_;
};
} // namespace MMI
} // namespace OHOS
#endif // JOYSTICK_LAYOUT_MAP_BUILDER_H
