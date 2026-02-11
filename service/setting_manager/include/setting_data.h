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

#ifndef SETTING_DATA_H
#define SETTING_DATA_H

#include <string>
#include <unordered_map>
#include <utility>
#include <variant>

#include "json_parser.h"
#include "setting_types.h"
#include "setting_constants.h"

namespace OHOS {
namespace MMI {

// Use constants from SettingConstants namespace
using namespace SettingConstants;

using FieldValue = std::variant<int32_t, bool, std::string>;

struct SettingItem {
    std::string settingKey;
    std::unordered_map<std::string, FieldValue> fieldPairs;

    std::string ToJson() const;
    bool FromJson(const std::string& key, const std::string& jsonStr);
    void MergeFrom(const SettingItem& item);
    bool Contains(const std::string& field);
};

class SettingData {
public:
    SettingData() = default;
    SettingData(std::vector<SettingItem> settingItems) : settingItems_(settingItems) {}

    std::string GetVersion();
    bool MergeFrom(const SettingData& other);
    void MergeExistingItemFrom(const SettingData& other);
    bool SerializeToJson(const std::string& settingKey, std::string& settingValue);

    void AddSettingItem(const SettingItem& item);
    bool ContainsSetting(const std::string& key);
    std::vector<SettingItem> GetSettingItems() const;
    SettingItem GetSettingItem(const std::string& settingKey);

    bool ContainsField(const std::string& settingKey, const std::string& field);
    bool SetField(const std::string& settingKey, const std::string& field, const FieldValue& value);
    void SetAddFlag(bool flag);
    bool GetAddFlag();
    template<typename T>
    bool GetField(const std::string& settingKey, const std::string& field, T& value)
    {
        auto it = FindItem(settingKey);
        if (it == settingItems_.end()) {
            return false;
        }
        auto fieldIt = it->fieldPairs.find(field);
        if (fieldIt == it->fieldPairs.end()) {
            return false;
        }
        auto& variant = fieldIt->second;
        return std::visit([&value](auto&& arg) -> bool {
            using TArg = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<TArg, T>) {
                value = arg;
                return true;
            }
            return false;
            }, variant);
    }

private:
    std::vector<SettingItem>::iterator FindItem(const std::string& key);
    std::vector<SettingItem> settingItems_;
    bool isNewUser_ { false };
};
} // namespace MMI
} // namespace OHOS

#endif // SETTING_DATA_H