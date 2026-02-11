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

#include "setting_data.h"
#include <sstream>

namespace OHOS {
namespace MMI {
namespace {
}

std::string SettingItem::ToJson() const
{
    std::stringstream jsonStream;
    jsonStream << "{";
    bool isFirstField = true;
    for (const auto& [field, value] : fieldPairs) {
        if (!isFirstField) {
            jsonStream << ",";
        }
        jsonStream << "\"" << field << "\":";
        if (std::holds_alternative<int32_t>(value)) {
            jsonStream << (std::get<int32_t>(value));
        } else if (std::holds_alternative<bool>(value)) {
            jsonStream << ((std::get<bool>(value)) ? "true" : "false");
        } else if (std::holds_alternative<std::string>(value)) {
            jsonStream << "\"" << std::get<std::string>(value) << "\"";
        }
        isFirstField = false;
    }
    jsonStream << "}";
    return jsonStream.str();
}

bool SettingItem::FromJson(const std::string& key, const std::string& jsonStr)
{
    JsonParser parser(jsonStr.c_str());
    if (!cJSON_IsObject(parser.Get())) {
        return false;
    }
    fieldPairs.clear();
    cJSON* current = (parser.Get())->child;
    while (current) {
        std::string field = current->string;
        switch (current->type) {
            case cJSON_Number: {
                fieldPairs[field] = (int32_t)current->valueint;
                break;
            }
            case cJSON_True: {
                fieldPairs[field] = true;
                break;
            }
            case cJSON_False: {
                fieldPairs[field] = false;
                break;
            }
            case cJSON_String: {
                fieldPairs[field] = std::string(current->valuestring);
                break;
            }
            default: {
                break;
            }
        }
        current = current->next;
    }
    settingKey = key;
    return true;
}

bool SettingItem::Contains(const std::string& field)
{
    return fieldPairs.find(field) != fieldPairs.end();
}

// merge item的fieldPairs到当前的fieldPairs中
void SettingItem::MergeFrom(const SettingItem& item)
{
    for (const auto& [field, value] : item.fieldPairs) {
        auto it = fieldPairs.find(field);
        if (it == fieldPairs.end()) {
            fieldPairs.emplace(field, value);
        } else if (it->second != value) {
            it->second = value;
        }
    }
}

std::vector<SettingItem> SettingData::GetSettingItems() const
{
    return settingItems_;
}

bool SettingData::MergeFrom(const SettingData& other)
{
    bool changed = false;
    for (auto& otherItem : other.GetSettingItems()) {
        auto it = FindItem(otherItem.settingKey);
        if (it == settingItems_.end()) {
            settingItems_.emplace_back(otherItem);
            changed = true;
            continue;
        }

        for (const auto& [field, value] : otherItem.fieldPairs) {
            auto fieldIt = it->fieldPairs.find(field);
            if (fieldIt == it->fieldPairs.end()) {
                it->fieldPairs.emplace(field, value);
                changed = true;
            } else if (fieldIt->second != value) {
                fieldIt->second = value;
                changed = true;
            }
        }
    }
    return changed;
}

void SettingData::MergeExistingItemFrom(const SettingData& other)
{
    for (const auto& otherItem : other.GetSettingItems()) {
        auto it = FindItem(otherItem.settingKey);
        if (it != settingItems_.end()) {
            // Only merge if the item exists in current SettingData
            for (const auto& [field, value] : otherItem.fieldPairs) {
                auto fieldIt = it->fieldPairs.find(field);
                if (fieldIt == it->fieldPairs.end()) {
                    it->fieldPairs.emplace(field, value);
                } else if (fieldIt->second != value) {
                    fieldIt->second = value;
                }
            }
        }
        // If item doesn't exist, skip it (don't add new items)
    }
}

bool SettingData::ContainsField(const std::string& settingKey, const std::string& field)
{
    auto it = FindItem(settingKey);
    return it != settingItems_.end() && it->fieldPairs.find(field) != it->fieldPairs.end();
}

bool SettingData::SetField(const std::string& settingKey, const std::string& field, const FieldValue& value)
{
    auto it = FindItem(settingKey);
    if (it != settingItems_.end()) {
        auto fieldIt = it->fieldPairs.find(field);
        if (fieldIt != it->fieldPairs.end()) {
            if (it->fieldPairs[field] == value) {
                return false;
            }
            fieldIt->second = value;
        } else {
            it->fieldPairs.emplace(field, value);
        }
    } else {
        settingItems_.emplace_back(SettingItem{
            .settingKey = settingKey,
            .fieldPairs = {{field, value}}
        });
    }
    return true;
}

std::vector<SettingItem>::iterator SettingData::FindItem(const std::string& key)
{
    return std::find_if(settingItems_.begin(), settingItems_.end(),
        [&key](const SettingItem& item) {
            return item.settingKey == key;
    });
}

void SettingData::AddSettingItem(const SettingItem& item)
{
    auto it = FindItem(item.settingKey);
    if (it != settingItems_.end()) {
        it->settingKey = item.settingKey;
        it->fieldPairs = item.fieldPairs;
    } else {
        settingItems_.emplace_back(item);
    }
}

bool SettingData::ContainsSetting(const std::string& settingKey)
{
    return FindItem(settingKey) != settingItems_.end();
}

void SettingData::SetAddFlag(bool flag)
{
    isNewUser_ = flag;
}

bool SettingData::GetAddFlag()
{
    return isNewUser_;
}

SettingItem SettingData::GetSettingItem(const std::string& settingKey)
{
    SettingItem item;
    auto it = FindItem(settingKey);
    if (it == settingItems_.end()) {
        return item;
    }
    item = *it;
    return item;
}

std::string SettingData::GetVersion()
{
    std::string mouseVersion = "";
    std::string touchpadVersion = "";
    std::string keyboardVersion = "";
    if (GetField(MOUSE_KEY_SETTING, FIELD_VERSION, mouseVersion) &&
        (mouseVersion == VERSION_NUMBERS_LATEST) &&
        GetField(TOUCHPAD_KEY_SETTING, FIELD_VERSION, touchpadVersion) &&
        (touchpadVersion == VERSION_NUMBERS_LATEST) &&
        GetField(KEYBOARD_KEY_SETTING, FIELD_VERSION, keyboardVersion) &&
        (keyboardVersion == VERSION_NUMBERS_LATEST)) {
        return VERSION_NUMBERS_LATEST;
    }
    return VERSION_NUMBERS_INITIAL;
}

bool SettingData::SerializeToJson(const std::string& settingKey, std::string& settingValue)
{
    auto it = FindItem(settingKey);
    if (it == settingItems_.end()) {
        return false;
    }
    settingValue = it->ToJson();
    return true;
}
} // namespace MMI
} // namespace OHOS