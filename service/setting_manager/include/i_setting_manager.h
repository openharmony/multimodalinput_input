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

#ifndef I_SETTING_MANAGER_H
#define I_SETTING_MANAGER_H

#include <memory>
#include <mutex>
#include <string>

#include "nocopyable.h"
#include "setting_types.h"

namespace OHOS {
namespace MMI {
class ISettingManager {
public:
    DISALLOW_COPY_AND_MOVE(ISettingManager);

    ISettingManager() = default;
    virtual ~ISettingManager() = default;

    virtual void Initialize() = 0;

    virtual bool SetIntValue(int32_t userId, const std::string& settingKey, const std::string& field,
        int32_t value) = 0;
    virtual bool GetIntValue(int32_t userId, const std::string& settingKey, const std::string& field,
        int32_t& value) = 0;
    virtual bool SetBoolValue(int32_t userId, const std::string& settingKey, const std::string& field, bool value) = 0;
    virtual bool GetBoolValue(int32_t userId, const std::string& settingKey, const std::string& field, bool& value) = 0;
    virtual void OnDataShareReady() = 0;
    virtual void OnSwitchUser(int32_t userId) = 0;
    virtual void OnAddUser(int32_t userId) = 0;
    virtual void OnRemoveUser(int32_t userId) = 0;
    static std::shared_ptr<ISettingManager> GetInstance();

private:
    static std::shared_ptr<ISettingManager> instance_;
    static std::once_flag initFlag_;
    static void Create();
};
#define INPUT_SETTING_MANAGER ::OHOS::MMI::ISettingManager::GetInstance()
} // namespace MMI
} // namespace OHOS

#endif // I_SETTING_MANAGER_H