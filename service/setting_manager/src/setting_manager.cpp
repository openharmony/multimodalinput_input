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

#include "setting_manager.h"

#include "product_name_definition.h"
#include "setting_constants.h"
#include <iomanip>
#include <memory>

#include "account_manager.h"
#include "mmi_log.h"
#include "setting_data_migrator.h"
#include "setting_storage.h"
#include "touchpad_transform_processor.h"
#include "i_input_service_context.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SettingManager"
#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER

namespace OHOS {
namespace MMI {
namespace {
using namespace SettingConstants;

const std::unordered_map<std::string, std::set<std::string>> SETTING_KEY_FIELD_MAP = {
    {MOUSE_KEY_SETTING, MOUSE_SETTING_FIELDS},
    {TOUCHPAD_KEY_SETTING, TOUCHPAD_SETTING_FIELDS},
    {KEYBOARD_KEY_SETTING, KEYBOARD_SETTING_FIELDS}};
constexpr bool BOOL_DEFAULT{true};
constexpr int32_t POINTER_SPEED_DEFAULT{10};
constexpr int32_t MOUSE_SCROLL_ROWS_DEFAULT{3};
constexpr int32_t POINTER_COLOR_DEFAULT{-1};
constexpr int32_t POINTER_SIZE_DEFAULT{1};
constexpr int32_t POINTER_SIZE_FOLD_PC_DEFAULT{2};
constexpr int32_t PRIMARY_BUTTON_DEFAULT{0};
constexpr int32_t POINTER_STYLE_DEFAULT{0};

constexpr int32_t TOUCHPAD_SCROLL_ROWS_DEFAULT{3};
constexpr int32_t TOUCHPAD_POINTER_SPEED_DEFAULT{6};

constexpr int32_t KEYBOARD_REPEATRATE_DEFAULT{50};
constexpr int32_t KEYBOARD_REPEATDELAY_DEFAULT{500};
static int32_t g_defaultPointerSize =
    ((SYS_GET_DEVICE_TYPE_PARAM == DEVICE_TYPE_FOLD_PC) ? POINTER_SIZE_FOLD_PC_DEFAULT : POINTER_SIZE_DEFAULT);
}  // namespace

std::shared_ptr<ISettingManager> ISettingManager::instance_;
std::once_flag ISettingManager::initFlag_;

std::shared_ptr<ISettingManager> ISettingManager::GetInstance()
{
    std::call_once(initFlag_, &ISettingManager::Create);
    return instance_;
}

void ISettingManager::Create()
{
    instance_ = std::make_shared<SettingManager>();
}

void SettingManager::Initialize()
{
    MMI_HILOGI("SettingManager init");
    SettingItem mouseItem = {.settingKey = MOUSE_KEY_SETTING,
        .fieldPairs = {
            {FIELD_MOUSE_SCROLL_ROWS, MOUSE_SCROLL_ROWS_DEFAULT},
            {FIELD_MOUSE_PRIMARY_BUTTON, PRIMARY_BUTTON_DEFAULT},
            {FIELD_MOUSE_POINTER_SPEED, POINTER_SPEED_DEFAULT},
            {FIELD_MOUSE_HOVER_SCROLL_STATE, BOOL_DEFAULT},
            {FIELD_MOUSE_POINTER_COLOR, POINTER_COLOR_DEFAULT},
            {FIELD_MOUSE_POINTER_SIZE, g_defaultPointerSize},
            {FIELD_MOUSE_POINTER_STYLE, POINTER_STYLE_DEFAULT},
            {FIELD_MOUSE_SCROLL_DIRECTION, BOOL_DEFAULT},
        }};

    SettingItem touchpadItem = {.settingKey = TOUCHPAD_KEY_SETTING,
        .fieldPairs = {
            {FIELD_TOUCHPAD_SCROLL_ROWS, TOUCHPAD_SCROLL_ROWS_DEFAULT},
            {FIELD_TOUCHPAD_THREE_FINGERTAP_SWITCH, BOOL_DEFAULT},
            {FIELD_TOUCHPAD_RIGHT_CLICK_TYPE, TOUCHPAD_TWO_FINGER_TAP_OR_RIGHT_BUTTON},
            {FIELD_TOUCHPAD_DOUBLE_TAP_AND_DRAG, BOOL_DEFAULT},
            {FIELD_TOUCHPAD_POINTER_SPEED, TOUCHPAD_POINTER_SPEED_DEFAULT},
            {FIELD_TOUCHPAD_TAP_SWITCH, BOOL_DEFAULT},
            {FIELD_TOUCHPAD_SCROLL_DIRECTION, BOOL_DEFAULT},
            {FIELD_TOUCHPAD_SCROLL_SWITCH, BOOL_DEFAULT},
            {FIELD_TOUCHPAD_PINCH_SWITCH, BOOL_DEFAULT},
            {FIELD_TOUCHPAD_SWIPE_SWITCH, BOOL_DEFAULT},
        }};

    SettingItem keyboardItem = {.settingKey = KEYBOARD_KEY_SETTING,
        .fieldPairs = {{FIELD_KEYBOARD_REPEAT_RATE, KEYBOARD_REPEATRATE_DEFAULT},
            {FIELD_KEYBOARD_REPEAT_RATE_DELAY, KEYBOARD_REPEATDELAY_DEFAULT}}};

    defaultSettingData_ = SettingData({mouseItem, touchpadItem, keyboardItem});

    if (ffrtHandler_ == nullptr) {
        ffrtHandler_ = std::make_shared<ffrt::queue>("InputSettingManager");
    }
}

void SettingManager::OnDataShareReady()
{
    MMI_HILOGI("In data share ready");
    if (databaseReadyFlag_.load()) {
        MMI_HILOGI("The database ready event has been received");
        return;
    }
    if (ffrtHandler_ == nullptr) {
        ffrtHandler_ = std::make_shared<ffrt::queue>("InputSettingManager");
    }
    ffrtHandler_->submit([this] {
        flushFlag_.store(true);
        int32_t userId = ACCOUNT_MGR->QueryCurrentAccountId();
        MMI_HILOGI("Run task in data share ready, current id:%{private}d", userId);
        ReadSettingData(userId);
        if (GetVersion(userId) != VERSION_NUMBERS_LATEST) {
            MMI_HILOGI("Migrate settings for all user");
            INPUT_SETTING_MIGRATOR.Initialize(defaultSettingData_);
            if (!INPUT_SETTING_MIGRATOR.Migrator()) {
                MMI_HILOGE("MigrateSettings failed");
            }
            ReadSettingData(userId);
        }
        CommitStagedChanges();
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
        TouchPadTransformProcessor::OnDataShareReady(userId);
#endif  // OHOS_BUILD_ENABLE_TOUCHPAD
        flushFlag_.store(false);
        databaseReadyFlag_.store(true);
    });
}

void SettingManager::OnSwitchUser(int32_t userId)
{
    MMI_HILOGI("In switch, id:%{private}d", userId);
    if (!databaseReadyFlag_.load()) {
        MMI_HILOGW("Data share not ready, id:%{private}d", userId);
        return;
    }
    if (ffrtHandler_ == nullptr) {
        ffrtHandler_ = std::make_shared<ffrt::queue>("InputSettingManager");
    }
    ffrtHandler_->submit([this, userId] {
        MMI_HILOGI("Run task on switch, id:%{private}d", userId);
        flushFlag_.store(true);
        if (CheckAddUser(userId)) {
            MMI_HILOGI("Add id switch, id:%{private}d", userId);
            flushFlag_.store(false);
            return;
        }
        ReadSettingData(userId);
        if (GetVersion(userId) != VERSION_NUMBERS_LATEST) {
            MMI_HILOGI("Need migrateSettings");
            if (!INPUT_SETTING_MIGRATOR.MigratorUserData(userId)) {
                MMI_HILOGE("MigrateSettings failed");
            }
            ReadSettingData(userId);
        }
        CommitStagedChanges();
#ifdef OHOS_BUILD_ENABLE_TOUCHPAD
        TouchPadTransformProcessor::OnSwitchUser(userId);
#endif  // OHOS_BUILD_ENABLE_TOUCHPAD
        flushFlag_.store(false);
    });
}

bool SettingManager::CheckAddUser(int32_t userId)
{
    if (cacheSettingMap_.find(userId) == cacheSettingMap_.end()) {
        MMI_HILOGI("Can not find id:%{private}d in cache", userId);
        return false;
    }
    SettingData data;
    {
        std::lock_guard<std::mutex> cacheGuard(cacheMapMutex_);
        data = cacheSettingMap_[userId];
    }
    if (!data.GetAddFlag()) {
        MMI_HILOGI("Not new id:%{private}d", userId);
        return false;
    }
    std::string settingVal = "";
    for (auto& key : SETTING_KEYS) {
        INPUT_SETTING_STORAGE.Read(userId, key, settingVal);
        std::string value = "";
        data.SerializeToJson(key, value);
        if (settingVal != value) {
            INPUT_SETTING_STORAGE.Write(userId, key, value);
        }
    }
    data.SetAddFlag(false);
    return true;
}

void SettingManager::OnAddUser(int32_t userId)
{
    MMI_HILOGI("In add, id:%{private}d", userId);
    if (databaseReadyFlag_.load()) {
        if (ffrtHandler_ == nullptr) {
            ffrtHandler_ = std::make_shared<ffrt::queue>("InputSettingManager");
        }
        ffrtHandler_->submit([this, userId] {
            MMI_HILOGI("Run task on add, id:%{private}d", userId);
            std::vector<SettingItem> items;
            for (auto &key : SETTING_KEYS) {
                SettingItem item = {.settingKey = key, .fieldPairs = {{FIELD_VERSION, VERSION_NUMBERS_LATEST}}};
                INPUT_SETTING_STORAGE.Write(userId, key, item.ToJson());
                items.emplace_back(item);
            }
            SettingData data(items);
            data.SetAddFlag(true);
            {
                std::lock_guard<std::mutex> guard(cacheMapMutex_);
                cacheSettingMap_[userId] = data;
            }
        });
    }
}

void SettingManager::OnRemoveUser(int32_t userId)
{
    MMI_HILOGI("In remove, id:%{private}d", userId);
    std::lock_guard<std::mutex> guard(cacheMapMutex_);
    if (auto it = cacheSettingMap_.find(userId); it != cacheSettingMap_.end()) {
        cacheSettingMap_.erase(it);
    }
}

void SettingManager::CommitStagedChanges()
{
    MMI_HILOGI("In CommitStagedChanges");
    std::unordered_map<int32_t, SettingData> commitDataMap;
    {
        std::lock_guard<std::mutex> guard(tempMapMutex_);
        if (tempSettingsMap_.empty()) {
            return;
        }
        commitDataMap = std::move(tempSettingsMap_);
    }

    MergeToCommitData(commitDataMap);

    for (auto &[userId, settingData] : commitDataMap) {
        for (auto &item : settingData.GetSettingItems()) {
            std::string valueStr;
            if (settingData.SerializeToJson(item.settingKey, valueStr)) {
                INPUT_SETTING_STORAGE.Write(userId, item.settingKey, valueStr);
            }
        }
    }
}

void SettingManager::MergeToCommitData(std::unordered_map<int32_t, SettingData> &commitDataMap)
{
    std::lock_guard<std::mutex> cacheGuard(cacheMapMutex_);
    for (auto &[userId, commitSettingData] : commitDataMap) {
        auto cacheIter = cacheSettingMap_.find(userId);
        if (cacheIter != cacheSettingMap_.end()) {
            // Only merge items that exist in staged data (incremental changes)
            // Cached items that don't exist in staged data will not be merged
            commitSettingData.MergeExistingItemFrom(cacheIter->second);
        }
    }
}

std::string SettingManager::GetVersion(int32_t userId)
{
    std::lock_guard<std::mutex> guard(cacheMapMutex_);
    auto iter = cacheSettingMap_.find(userId);
    if (iter == cacheSettingMap_.end()) {
        MMI_HILOGE("Not find user data");
        return VERSION_NUMBERS_INITIAL;
    }
    return iter->second.GetVersion();
}

void SettingManager::ReadSettingData()
{
    std::vector<int32_t> userIds = ACCOUNT_MGR->QueryAllCreatedOsAccounts();
    if (userIds.empty()) {
        MMI_HILOGE("Query ids is empty");
        return;
    }
    for (auto &userId : userIds) {
        ReadSettingData(userId);
    }
}

void SettingManager::ReadSettingData(int32_t userId)
{
    SettingData data;

    // Batch query all keys at once using IN clause
    std::vector<std::string> keys(SETTING_KEYS.begin(), SETTING_KEYS.end());
    std::unordered_map<std::string, std::string> resultMap;
    if (INPUT_SETTING_STORAGE.ReadBatch(userId, keys, resultMap)) {
        for (const auto& [settingKey, settingVal] : resultMap) {
            SettingItem item;
            if (item.FromJson(settingKey, settingVal)) {
                data.AddSettingItem(item);
            }
            MMI_HILOGI(
                "id:%{private}d, key:%{public}s, value:%{public}s", userId, settingKey.c_str(), settingVal.c_str());
        }
    }

    std::lock_guard<std::mutex> guard(cacheMapMutex_);
    cacheSettingMap_[userId] = data;
}

bool SettingManager::SetIntValue(int32_t userId, const std::string &settingKey, const std::string &field, int32_t value)
{
    return SetValueInner(userId, settingKey, field, value);
}

bool SettingManager::GetIntValue(
    int32_t userId, const std::string &settingKey, const std::string &field, int32_t &value)
{
    return GetValueInner(userId, settingKey, field, value);
}

bool SettingManager::SetBoolValue(int32_t userId, const std::string &settingKey, const std::string &field, bool value)
{
    return SetValueInner(userId, settingKey, field, value);
}

bool SettingManager::GetBoolValue(int32_t userId, const std::string &settingKey, const std::string &field, bool &value)
{
    return GetValueInner(userId, settingKey, field, value);
}

template <typename T>
bool SettingManager::SetValueInner(
    int32_t userId, const std::string &settingKey, const std::string &field, const T &value)
{
    if (!IsParamsValid(userId, settingKey, field)) {
        MMI_HILOGE("Invalid param, field:%{public}s", field.c_str());
        return false;
    }

    // If database is not ready or refreshing cache, save to temp storage
    if (ShouldWriteToTemp()) {
        MMI_HILOGI("Save to temp,id:%{private}d, field:%{public}s, value:%{public}d",
            userId, field.c_str(), static_cast<int32_t>(value));
        SaveToTemp(userId, settingKey, field, value);
        return true;
    }

    // Prepare data for writing
    SettingData settingData;
    if (!UpdateSettingData(userId, settingKey, field, value, settingData)) {
        MMI_HILOGI("No need write, same value, field:%{public}s", field.c_str());
        return true;
    }

    // Write to database
    if (!WriteToDatabase(userId, settingKey, settingData)) {
        return false;
    }

    // Update cache after successful database write
    SaveToCache(userId, settingData);
    MMI_HILOGI("Set field:%{public}s success, id:%{private}d", field.c_str(), userId);
    return true;
}

bool SettingManager::ShouldWriteToTemp() const
{
    return flushFlag_.load() || !databaseReadyFlag_.load();
}

bool SettingManager::WriteToDatabase(int32_t userId, const std::string& settingKey, SettingData& settingData)
{
    std::string settingVal = "";
    if (!settingData.SerializeToJson(settingKey, settingVal)) {
        MMI_HILOGE("SerializeToJson failed, settingKey:%{public}s", settingKey.c_str());
        return false;
    }

    if (!INPUT_SETTING_STORAGE.Write(userId, settingKey, settingVal)) {
        MMI_HILOGE("Write to database failed, key:%{public}s", settingKey.c_str());
        return false;
    }

    return true;
}

template <typename T>
bool SettingManager::GetValueInner(int32_t userId, const std::string &settingKey, const std::string &field, T &value)
{
    if (!IsParamsValid(userId, settingKey, field)) {
        MMI_HILOGE("Invalid param");
        return false;
    }
    if (flushFlag_.load() || !databaseReadyFlag_.load()) {
        {
            std::lock_guard<std::mutex> guard(tempMapMutex_);
            if (auto iter = tempSettingsMap_.find(userId); iter != tempSettingsMap_.end()) {
                auto settingData = iter->second;
                if (settingData.ContainsField(settingKey, field)) {
                    settingData.GetField(settingKey, field, value);
                    MMI_HILOGI("Get field:%{public}s, value:%{public}d success, id:%{private}d, in temp",
                        field.c_str(), static_cast<int32_t>(value), userId);
                    return true;
                }
            }
        }
    }
    {
        std::lock_guard<std::mutex> guard(cacheMapMutex_);
        if (auto iter = cacheSettingMap_.find(userId); iter != cacheSettingMap_.end()) {
            auto settingData = iter->second;
            if (settingData.ContainsField(settingKey, field)) {
                settingData.GetField(settingKey, field, value);
                MMI_HILOGI("Get field:%{public}s, value:%{public}d success, id:%{private}d in cache",
                    field.c_str(), static_cast<int32_t>(value), userId);
                return true;
            }
        }
    }
    MMI_HILOGI("Get field:%{public}s,success, id:%{private}d, from default",
        field.c_str(), userId);
    return defaultSettingData_.GetField(settingKey, field, value);
}

template <typename T>
void SettingManager::SaveToTemp(int32_t userId, const std::string &settingKey, const std::string &field, const T &value)
{
    std::lock_guard<std::mutex> guard(tempMapMutex_);
    if (auto iter = tempSettingsMap_.find(userId); iter == tempSettingsMap_.end()) {
        SettingData data;
        data.SetField(settingKey, field, value);
        tempSettingsMap_[userId] = data;
    } else {
        tempSettingsMap_[userId].SetField(settingKey, field, value);
    }
}

void SettingManager::SaveToCache(int32_t userId, SettingData &settingData)
{
    std::lock_guard<std::mutex> guard(cacheMapMutex_);
    cacheSettingMap_[userId] = settingData;
}

template <typename T>
bool SettingManager::UpdateSettingData(
    int32_t userId, const std::string &settingKey, const std::string &field, const T &value, SettingData &settingData)
{
    std::lock_guard<std::mutex> guard(cacheMapMutex_);
    auto iter = cacheSettingMap_.find(userId);
    if (iter == cacheSettingMap_.end()) {
        std::vector<SettingItem> items;
        items.emplace_back(SettingItem {
            .settingKey = settingKey,
            .fieldPairs = {
                {FIELD_VERSION, VERSION_NUMBERS_LATEST},
                {field, value}
            }});
        settingData = SettingData(items);
        return true;
    } else {
        // Create a copy to avoid modifying cache until database write succeeds
        // This ensures cache consistency if database write fails
        settingData = SettingData(cacheSettingMap_[userId].GetSettingItems());
        if (!settingData.SetField(settingKey, field, value)) {
            MMI_HILOGE("Same value, no need write, field:%{public}s, id:%{private}d", field.c_str(), userId);
            return false;
        }
    }
    return true;
}

bool SettingManager::IsParamsValid(int32_t userId, const std::string &settingKey, const std::string &field)
{
    if (userId < 0 || userId > MAX_USER_ID || settingKey.empty() || field.empty()) {
        MMI_HILOGE("Invalid param, settingKey:%{public}s, field:%{public}s, id:%{private}d",
            settingKey.c_str(), field.c_str(), userId);
        return false;
    }

    auto iter = SETTING_KEY_FIELD_MAP.find(settingKey);
    if (iter == SETTING_KEY_FIELD_MAP.end()) {
        MMI_HILOGE("The settingkey:%{public}s is not supported", settingKey.c_str());
        return false;
    }

    const auto &fieldSet = iter->second;
    if (fieldSet.find(field) == fieldSet.end()) {
        MMI_HILOGE("This field:%{public}s does not belong to settingkey:%{public}s", field.c_str(), settingKey.c_str());
        return false;
    }
    return true;
}
}  // namespace MMI
}  // namespace OHOS