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
#pragma once
#include <set>
#include <string>

#include <preferences_helper.h>
#include "setting_data.h"

namespace OHOS {
namespace MMI {

class SettingDataMigrator {
public:
    static SettingDataMigrator& GetInstance()
    {
        static SettingDataMigrator instance;
        return instance;
    }
    void Initialize(const SettingData& data);

    bool Migrator();
    bool MigratorUserData(int32_t userId);

private:
    bool MigrateSettings(const std::string& filePath, const std::string& settingKey,
        const std::set<std::string>& settingFields);
    bool MigrateUserSettings(int32_t userId, const std::string& filePath,
        const std::string& settingKey, const std::set<std::string>& settingFields);
    bool CreateNewSettingFromFile(const std::string& filePath,
        const std::string& settingKey, const std::set<std::string>& settingFields, SettingItem& item);
    bool UpdateExistingSetting(const std::string& settingKey,
        const std::string& settingVal, SettingItem& item, bool& needWrite);
    int32_t GetRightClickTypeVal(std::shared_ptr<NativePreferences::Preferences>& touchpadPref);

    SettingDataMigrator() = default;
    ~SettingDataMigrator() = default;
    SettingDataMigrator(const SettingDataMigrator&) = delete;
    SettingDataMigrator& operator=(const SettingDataMigrator&) = delete;
    SettingData defaultSettingData_;
    int32_t mousePrimaryButton_ = 0;
};

#define INPUT_SETTING_MIGRATOR ::OHOS::MMI::SettingDataMigrator::GetInstance()
}
}