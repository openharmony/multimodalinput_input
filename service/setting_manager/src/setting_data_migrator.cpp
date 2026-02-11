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

#include "setting_data_migrator.h"

#include <algorithm>
#include <unistd.h>

#include "account_manager.h"
#include "mmi_log.h"
#include "setting_types.h"
#include "setting_storage.h"
#include "setting_constants.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SettingDataMigrator"
#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER

namespace OHOS {
namespace MMI {
namespace {
using namespace SettingConstants;

constexpr int32_t RIGHT_MENU_TYPE_INDEX_V2{1};
constexpr int32_t PRIMARY_BUTTON_DEFAULT{0};
}  // namespace

void SettingDataMigrator::Initialize(const SettingData &data)
{
    defaultSettingData_ = data;
}

bool SettingDataMigrator::Migrator()
{
    bool isSuccess = true;
    if (!MigrateSettings(GLOBAL_MOUSE_FILE_PATH, MOUSE_KEY_SETTING, MOUSE_SETTING_FIELDS)) {
        MMI_HILOGE("MigrateSettings failed, key:%{public}s", MOUSE_KEY_SETTING.c_str());
        isSuccess = false;
    }

    if (!MigrateSettings(GLOBAL_TOUCHPAD_FILE_PATH, TOUCHPAD_KEY_SETTING, TOUCHPAD_SETTING_FIELDS)) {
        MMI_HILOGE("MigrateSettings failed, key:%{public}s", TOUCHPAD_KEY_SETTING.c_str());
        isSuccess = false;
    }

    if (!MigrateSettings(GLOBAL_KEYBOARD_FILE_PATH, KEYBOARD_KEY_SETTING, KEYBOARD_SETTING_FIELDS)) {
        MMI_HILOGE("MigrateSettings failed, key:%{public}s", KEYBOARD_KEY_SETTING.c_str());
        isSuccess = false;
    }
    return isSuccess;
}

bool SettingDataMigrator::MigratorUserData(int32_t userId)
{
    bool isSuccess = true;
    if (!MigrateUserSettings(userId, GLOBAL_MOUSE_FILE_PATH, MOUSE_KEY_SETTING, MOUSE_SETTING_FIELDS)) {
        MMI_HILOGE("MigrateUserSettings failed, key:%{public}s", MOUSE_KEY_SETTING.c_str());
        isSuccess = false;
    }

    if (!MigrateUserSettings(userId, GLOBAL_TOUCHPAD_FILE_PATH, TOUCHPAD_KEY_SETTING, TOUCHPAD_SETTING_FIELDS)) {
        MMI_HILOGE("MigrateUserSettings failed, key:%{public}s", TOUCHPAD_KEY_SETTING.c_str());
        isSuccess = false;
    }

    if (!MigrateUserSettings(userId, GLOBAL_KEYBOARD_FILE_PATH, KEYBOARD_KEY_SETTING, KEYBOARD_SETTING_FIELDS)) {
        MMI_HILOGE("MigrateUserSettings failed, key:%{public}s", KEYBOARD_KEY_SETTING.c_str());
        isSuccess = false;
    }
    return isSuccess;
}

bool SettingDataMigrator::MigrateSettings(
    const std::string &filePath, const std::string &settingKey, const std::set<std::string> &settingFields)
{
    std::vector<int32_t> userIds = ACCOUNT_MGR->QueryAllCreatedOsAccounts();
    if (userIds.empty()) {
        MMI_HILOGE("Query ids is empty");
        return false;
    }
    for (auto &userId : userIds) {
        if (!MigrateUserSettings(userId, filePath, settingKey, settingFields)) {
            MMI_HILOGE("Migrate settings failed for id:%{private}d, key:%{public}s", userId, settingKey.c_str());
            continue;
        }
    }
    return true;
}

bool SettingDataMigrator::MigrateUserSettings(int32_t userId, const std::string &filePath,
    const std::string &settingKey, const std::set<std::string> &settingFields)
{
    MMI_HILOGI("MigrateUserSettings, id:%{private}d, key:%{public}s", userId, settingKey.c_str());
    std::string settingVal;
    SettingItem item;
    bool needWrite = false;

    if (!INPUT_SETTING_STORAGE.Read(userId, settingKey, settingVal)) {
        if (!CreateNewSettingFromFile(filePath, settingKey, settingFields, item)) {
            MMI_HILOGE("CreateNewSettingFromFile failed, id:%{private}d, key:%{public}s", userId, settingKey.c_str());
            return false;
        }
        needWrite = true;
    } else {
        if (!UpdateExistingSetting(settingKey, settingVal, item, needWrite) ||  !needWrite) {
            MMI_HILOGI("No need update, id:%{private}d, key:%{public}s", userId, settingKey.c_str());
            return true;
        }
    }
    if (needWrite) {
        return INPUT_SETTING_STORAGE.Write(userId, settingKey, item.ToJson());
    }
    return true;
}

bool SettingDataMigrator::CreateNewSettingFromFile(const std::string &filePath, const std::string &settingKey,
    const std::set<std::string> &settingFields, SettingItem &item)
{
    MMI_HILOGI("CreateNewSettingFromFile, path:%{private}s, key:%{public}s", filePath.c_str(), settingKey.c_str());
    item.settingKey = settingKey;
    item.fieldPairs.emplace(FIELD_VERSION, VERSION_NUMBERS_LATEST);

    if ((access(filePath.c_str(), F_OK) != 0)) {
        MMI_HILOGW("File does not exist and does not need to be migrated, key:%{public}s", settingKey.c_str());
        return true;
    }
    int32_t errCode = RET_OK;
    auto pref = NativePreferences::PreferencesHelper::GetPreferences(filePath, errCode);
    if (!pref || errCode != RET_OK) {
        MMI_HILOGE("GetPreferences failed for file:%{public}s, errCode:%{public}d", filePath.c_str(), errCode);
        return false;
    }

    for (const auto &field : settingFields) {
        if (!pref->HasKey(field)) {
            continue;
        }
        if (field == FIELD_TOUCHPAD_RIGHT_CLICK_TYPE) {
            int32_t value = GetRightClickTypeVal(pref);
            item.fieldPairs.emplace(field, value);
        }
        if (std::find(SETTING_FIELDS_BOOL.begin(), SETTING_FIELDS_BOOL.end(), field) != SETTING_FIELDS_BOOL.end()) {
            bool value = true;
            defaultSettingData_.GetField(settingKey, field, value);
            value = pref->GetBool(field, value);
            item.fieldPairs.emplace(field, value);
        } else {
            int32_t value = -1;
            defaultSettingData_.GetField(settingKey, field, value);
            value = pref->GetInt(field, value);
            item.fieldPairs.emplace(field, value);
            if (field == FIELD_MOUSE_PRIMARY_BUTTON) {
                mousePrimaryButton_ = value;
                MMI_HILOGI("mousePrimaryButton:%{public}d", mousePrimaryButton_);
            }
        }
    }

    return true;
}

bool SettingDataMigrator::UpdateExistingSetting(
    const std::string &settingKey, const std::string &settingVal, SettingItem &item, bool &needWrite)
{
    if (!item.FromJson(settingKey, settingVal)) {
        MMI_HILOGE("ParseFromJson failed for setting:%{public}s", settingKey.c_str());
        return false;
    }

    if (!item.Contains(FIELD_VERSION)) {
        MMI_HILOGI("Add version");
        item.fieldPairs.emplace(FIELD_VERSION, VERSION_NUMBERS_LATEST);
        needWrite = true;
    }
    return true;
}

int32_t SettingDataMigrator::GetRightClickTypeVal(std::shared_ptr<NativePreferences::Preferences> &touchpadPref)
{
    std::vector<uint8_t> clickTypeVect = {TOUCHPAD_RIGHT_BUTTON, 0};
    clickTypeVect[RIGHT_MENU_TYPE_INDEX_V2] = mousePrimaryButton_ == PRIMARY_BUTTON_DEFAULT
                                                  ? TOUCHPAD_TWO_FINGER_TAP_OR_RIGHT_BUTTON
                                                  : TOUCHPAD_TWO_FINGER_TAP_OR_LEFT_BUTTON;
    clickTypeVect =
        static_cast<std::vector<uint8_t>>(touchpadPref->Get(FIELD_TOUCHPAD_RIGHT_CLICK_TYPE, clickTypeVect));
    return clickTypeVect[RIGHT_MENU_TYPE_INDEX_V2];
}
}  // namespace MMI
}  // namespace OHOS