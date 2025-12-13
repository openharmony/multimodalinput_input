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

#include "joystick_layout_map_builder.h"

#include <fstream>

#include "define_multimodal.h"
#include "joystick_event_processor.h"
#include "key_event.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickLayoutMapBuilder"

namespace OHOS {
namespace MMI {
std::unordered_map<int32_t, std::string> JoystickLayoutMapBuilder::keyNames_ {
    { KeyEvent::KEYCODE_BUTTON_THUMBL, "BUTTON_THUMBL" },
};

void JoystickLayoutMapBuilder::BuildJoystickLayoutMap(const JoystickLayoutMap &layout, const std::string &outputFile)
{
    auto jsonDoc = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_CreateObject(),
        [](cJSON *object) {
            if (object != nullptr) {
                cJSON_Delete(object);
            }
        });
    CHKPV(jsonDoc);
    WriteKeys(jsonDoc.get(), layout.keys_);
    WriteAxes(jsonDoc.get(), layout.axes_);
    SerializeJoystickLayoutMap(jsonDoc.get(), outputFile);
}

std::string JoystickLayoutMapBuilder::MapKeyName(int32_t keyCode)
{
    if (auto iter = keyNames_.find(keyCode); iter != keyNames_.cend()) {
        return iter->second;
    }
    return std::string();
}

void JoystickLayoutMapBuilder::SerializeJoystickLayoutMap(cJSON *jsonConfig, const std::string &outputFile)
{
    CHKPV(jsonConfig);
    auto sConfig = std::unique_ptr<char, std::function<void(char *)>>(
        cJSON_Print(jsonConfig),
        [](char *object) {
            if (object != nullptr) {
                cJSON_free(object);
            }
        });
    CHKPV(sConfig);
    std::ofstream ofs(outputFile, std::ios_base::out);
    if (ofs.is_open()) {
        ofs << sConfig.get();
        ofs.flush();
        ofs.close();
    }
}

void JoystickLayoutMapBuilder::WriteKeys(cJSON *jsonDoc,
    const std::unordered_map<int32_t, JoystickLayoutMap::Key> &keys)
{
    auto jsonKeys = cJSON_CreateArray();
    CHKPV(jsonKeys);
    if (!cJSON_AddItemToObject(jsonDoc, "KEYS", jsonKeys)) {
        cJSON_Delete(jsonKeys);
        return;
    }
    for (const auto &[code, key] : keys) {
        WriteKeyInfo(jsonKeys, code, key);
    }
}

void JoystickLayoutMapBuilder::WriteKeyInfo(cJSON *jsonKeys, int32_t rawCode, const JoystickLayoutMap::Key &keyInfo)
{
    auto jsonKey = cJSON_CreateObject();
    CHKPV(jsonKey);
    if (!cJSON_AddItemToArray(jsonKeys, jsonKey)) {
        cJSON_Delete(jsonKey);
        return;
    }
    auto jsonRawCode = cJSON_CreateNumber(rawCode);
    CHKPV(jsonRawCode);
    if (!cJSON_AddItemToObject(jsonKey, "RAWCODE", jsonRawCode)) {
        cJSON_Delete(jsonRawCode);
        return;
    }
    auto jsonKeyCode = cJSON_CreateString(JoystickLayoutMapBuilder::MapKeyName(keyInfo.keyCode_).c_str());
    CHKPV(jsonKeyCode);
    if (!cJSON_AddItemToObject(jsonKey, "KEYCODE", jsonKeyCode)) {
        cJSON_Delete(jsonKeyCode);
        return;
    }
}

void JoystickLayoutMapBuilder::WriteAxes(cJSON *jsonDoc,
    const std::unordered_map<int32_t, JoystickLayoutMap::AxisInfo> &axes)
{
    auto jsonAxes = cJSON_CreateArray();
    CHKPV(jsonAxes);
    if (!cJSON_AddItemToObject(jsonDoc, "AXES", jsonAxes)) {
        cJSON_Delete(jsonAxes);
        return;
    }
    for (const auto &[code, axis] : axes) {
        WriteAxisInfo(jsonAxes, code, axis);
    }
}

void JoystickLayoutMapBuilder::WriteAxisInfo(cJSON *jsonAxes,
    int32_t rawCode, const JoystickLayoutMap::AxisInfo &axisInfo)
{
    auto jsonAxis = cJSON_CreateObject();
    CHKPV(jsonAxis);
    if (!cJSON_AddItemToArray(jsonAxes, jsonAxis)) {
        cJSON_Delete(jsonAxis);
        return;
    }
    if (!WriteAxisMode(jsonAxis, axisInfo)) {
        return;
    }

    auto jsonRawCode = cJSON_CreateNumber(rawCode);
    CHKPV(jsonRawCode);
    if (!cJSON_AddItemToObject(jsonAxis, "RAWCODE", jsonRawCode)) {
        cJSON_Delete(jsonRawCode);
        return;
    }

    auto jsonAxisName = cJSON_CreateString(JoystickEventProcessor::MapAxisName(axisInfo.axis_).c_str());
    CHKPV(jsonAxisName);
    if (!cJSON_AddItemToObject(jsonAxis, "AXIS", jsonAxisName)) {
        cJSON_Delete(jsonAxisName);
        return;
    }

    if (axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT) {
        auto jsonSplitValue = cJSON_CreateNumber(axisInfo.splitValue_);
        CHKPV(jsonSplitValue);
        if (!cJSON_AddItemToObject(jsonAxis, "SPLIT_VALUE", jsonSplitValue)) {
            cJSON_Delete(jsonSplitValue);
            return;
        }

        auto jsonHighAxis = cJSON_CreateString(JoystickEventProcessor::MapAxisName(axisInfo.highAxis_).c_str());
        CHKPV(jsonHighAxis);
        if (!cJSON_AddItemToObject(jsonAxis, "HIGH_AXIS", jsonHighAxis)) {
            cJSON_Delete(jsonHighAxis);
            return;
        }
    }

    if (axisInfo.flatOverride_ > 0) {
        auto jsonFlat = cJSON_CreateNumber(axisInfo.flatOverride_);
        CHKPV(jsonFlat);
        if (!cJSON_AddItemToObject(jsonAxis, "FLAT", jsonFlat)) {
            cJSON_Delete(jsonFlat);
            return;
        }
    }
}

bool JoystickLayoutMapBuilder::WriteAxisMode(cJSON *jsonAxis, const JoystickLayoutMap::AxisInfo &axisInfo)
{
    if (axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_INVERT) {
        auto jsonMode = cJSON_CreateString("INVERT");
        CHKPF(jsonMode);
        if (!cJSON_AddItemToObject(jsonAxis, "MODE", jsonMode)) {
            cJSON_Delete(jsonMode);
            return false;
        }
    } else if (axisInfo.mode_ == JoystickLayoutMap::AxisMode::AXIS_MODE_SPLIT) {
        auto jsonMode = cJSON_CreateString("SPLIT");
        CHKPF(jsonMode);
        if (!cJSON_AddItemToObject(jsonAxis, "MODE", jsonMode)) {
            cJSON_Delete(jsonMode);
            return false;
        }
    }
    return true;
}
} // namespace MMI
} // namespace OHOS
