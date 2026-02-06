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
#include <datashare_helper.h>
#include <mutex>
#include <string>
#include <unordered_map>

namespace OHOS {
namespace MMI {
class SettingStorage final {
public:
    static SettingStorage& GetInstance() {
        static SettingStorage instance;
        return instance;
    }

    // Writes specified key data to a specified user table
    bool Write(int32_t userId, const std::string& key, const std::string& value);

    // Reads specified key data in a specified user table
    bool Read(int32_t userId, const std::string& key, std::string& value);

    // Batch read multiple keys for a specified user table
    bool ReadBatch(int32_t userId, const std::vector<std::string>& keys,
                  std::unordered_map<std::string, std::string>& result);

private:
    SettingStorage() = default;
    ~SettingStorage();
    SettingStorage(const SettingStorage&) = delete;
    SettingStorage& operator=(const SettingStorage&) = delete;
    SettingStorage(SettingStorage&&) = delete;
    SettingStorage& operator=(SettingStorage&&) = delete;

    std::string AssembleUriUser(int32_t userId, const std::string &key) const;
    void ReleaseDataShareHelper();
    bool WriteDataInternal(int32_t userId, const std::string& key, const std::string& value);
    bool ReadDataInternal(int32_t userId, const std::string& key, std::string& value);
    std::shared_ptr<DataShare::DataShareHelper> GetHelper();
    std::shared_ptr<DataShare::DataShareHelper> CreateHelper();

    std::shared_ptr<DataShare::DataShareHelper> helper_ = nullptr;

    std::recursive_mutex helperMutex_;
};

#define INPUT_SETTING_STORAGE ::OHOS::MMI::SettingStorage::GetInstance()
} // namespace MMI
} // namespace OHOS