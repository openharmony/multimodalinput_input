/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef I_PREFERENCE_MANAGER_H
#define I_PREFERENCE_MANAGER_H

#include <memory>
#include <mutex>
#include "preferences_value.h"

namespace OHOS {
namespace MMI {
class IPreferenceManager {
public:
    IPreferenceManager() = default;
    virtual ~IPreferenceManager() = default;

    virtual int32_t InitPreferences() = 0;
    virtual int32_t GetIntValue(const std::string &key, int32_t defaultValue) = 0;
    virtual bool GetBoolValue(const std::string &key, bool defaultValue) = 0;
    virtual int32_t SetIntValue(const std::string &key, const std::string &setFile, int32_t setValue) = 0;
    virtual int32_t SetBoolValue(const std::string &key, const std::string &setFile, bool setValue) = 0;
    virtual int32_t GetShortKeyDuration(const std::string &key) = 0;
    virtual int32_t SetShortKeyDuration(const std::string &key, int32_t setValue) = 0;
    virtual bool IsInitPreference() = 0;
    virtual void UpdatePreferencesMap(const std::string &key, const std::string &setFile,
        int32_t setValue, std::string &filePath) = 0;
    virtual NativePreferences::PreferencesValue GetPreValue(const std::string &key,
        NativePreferences::PreferencesValue defaultValue) = 0;
    virtual int32_t SetPreValue(const std::string &key, const std::string &filePath,
        const NativePreferences::PreferencesValue &setValue) = 0;

    static std::shared_ptr<IPreferenceManager> GetInstance();

private:
    static std::mutex mutex_;
    static std::shared_ptr<IPreferenceManager> instance_;
};

#define PREFERENCES_MGR ::OHOS::MMI::IPreferenceManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // I_PREFERENCE_MANAGER_H