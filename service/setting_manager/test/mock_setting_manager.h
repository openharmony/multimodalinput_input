/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOCK_SETTING_MANAGER_H
#define MOCK_SETTING_MANAGER_H

#include <gmock/gmock.h>
#include "i_setting_manager.h"

namespace OHOS {
namespace MMI {

class MockSettingManager : public ISettingManager {
public:
    MockSettingManager() = default;
    ~MockSettingManager() override = default;

    MOCK_METHOD(void, Initialize, (), (override));
    MOCK_METHOD(bool, SetIntValue,
        (int32_t userId, const std::string& settingKey, const std::string& field, int32_t value), (override));
    MOCK_METHOD(bool, GetIntValue,
        (int32_t userId, const std::string& settingKey, const std::string& field, int32_t& value), (override));
    MOCK_METHOD(bool, SetBoolValue,
        (int32_t userId, const std::string& settingKey, const std::string& field, bool value), (override));
    MOCK_METHOD(bool, GetBoolValue,
        (int32_t userId, const std::string& settingKey, const std::string& field, bool& value), (override));
    MOCK_METHOD(void, OnDataShareReady, (), (override));
    MOCK_METHOD(void, OnSwitchUser, (int32_t userId), (override));
    MOCK_METHOD(void, OnAddUser, (int32_t userId), (override));
    MOCK_METHOD(void, OnRemoveUser, (int32_t userId), (override));
};

}  // namespace MMI
}  // namespace OHOS

#endif  // MOCK_SETTING_MANAGER_H
