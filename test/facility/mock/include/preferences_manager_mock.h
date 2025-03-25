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

#ifndef MULTIMODAL_INPUT_PREFERENCES_MANAGER_H
#define MULTIMODAL_INPUT_PREFERENCES_MANAGER_H

#include <gmock/gmock.h>
#include "nocopyable.h"

#include "i_preference_manager.h"

namespace OHOS {
namespace MMI {
class PreferencesManagerMock final : public IPreferenceManager {
public:
    PreferencesManagerMock() = default;
    ~PreferencesManagerMock() = default;
    DISALLOW_COPY_AND_MOVE(PreferencesManagerMock);

    MOCK_METHOD(int32_t, InitPreferences, ());
    MOCK_METHOD(bool, GetBoolValue, (const std::string&, bool));
    MOCK_METHOD(int32_t, GetIntValue, (const std::string&, int32_t));
    MOCK_METHOD(int32_t, SetIntValue, (const std::string&, const std::string&, int32_t));
    MOCK_METHOD(int32_t, SetBoolValue, (const std::string&, const std::string&, bool));
    MOCK_METHOD(int32_t, GetShortKeyDuration, (const std::string&));
    MOCK_METHOD(int32_t, SetShortKeyDuration, (const std::string&, int32_t));
    MOCK_METHOD(bool, IsInitPreference, ());

    static std::shared_ptr<PreferencesManagerMock> GetInstance();

private:
    static std::mutex mutex_;
    static std::shared_ptr<PreferencesManagerMock> instance_;
};

#define PREFERENCES_MGR_MOCK ::OHOS::MMI::PreferencesManagerMock::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_PREFERENCES_MANAGER_H
