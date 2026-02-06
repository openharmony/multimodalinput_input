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
#include <atomic>
#include <memory>
#include <string>
#include <unordered_map>

#include "i_setting_manager.h"
#include "ffrt_inner.h"
#include "setting_data.h"
#include "setting_types.h"

namespace OHOS {
namespace MMI {
class SettingManager : public ISettingManager {
public:
    SettingManager() = default;
    ~SettingManager() = default;
    DISALLOW_COPY_AND_MOVE(SettingManager);

    void Initialize() override;
    bool SetIntValue(int32_t userId, const std::string& settingKey, const std::string& field, int32_t value) override;
    bool GetIntValue(int32_t userId, const std::string& settingKey, const std::string& field, int32_t& value) override;
    bool SetBoolValue(int32_t userId, const std::string& settingKey, const std::string& field, bool value) override;
    bool GetBoolValue(int32_t userId, const std::string& settingKey, const std::string& field, bool& value) override;

    void OnDataShareReady() override;
    void OnSwitchUser(int32_t userId) override;
    void OnAddUser(int32_t userId) override;
    void OnRemoveUser(int32_t userId) override;

private:
    template<typename T>
    bool SetValueInner(int32_t userId, const std::string& settingKey, const std::string& field, const T& value);
    template<typename T>
    bool GetValueInner(int32_t userId, const std::string& settingKey, const std::string& field, T& value);
    bool IsParamsValid(int32_t userId, const std::string& settingKey, const std::string& field);
    std::string GetVersion(int32_t userId);
    void ReadSettingData(int32_t userId);
    void CommitStagedChanges();
    template<typename T>
    void SaveToTemp(int32_t userId, const std::string &settingKey, const std::string &field, const T &value);
    template<typename T>
    bool UpdateSettingData(int32_t userId, const std::string &settingKey, const std::string &field, const T &value,
        SettingData& settingData);
    void MergeToCommitData(std::unordered_map<int32_t, SettingData>& commitDataMap);
    void SaveToCache(int32_t userId, SettingData& settingData);
    bool CheckAddUser(int32_t userId);
    void ReadSettingData();

    // Helper methods for SetValueInner
    bool ShouldWriteToTemp() const;
    bool WriteToDatabase(int32_t userId, const std::string& settingKey, SettingData& settingData);

    std::unordered_map<int32_t, SettingData> cacheSettingMap_;
    std::unordered_map<int32_t, SettingData> tempSettingsMap_;
    SettingData defaultSettingData_;

    std::atomic<bool> flushFlag_ { false };
    std::atomic<bool> databaseReadyFlag_ { false };
    std::mutex cacheMapMutex_;
    std::mutex tempMapMutex_;
    std::shared_ptr<ffrt::queue> ffrtHandler_;
};
} // namespace MMI
} // namespace OHOS