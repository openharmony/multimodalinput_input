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

#include "preferences_manager_mock.h"

namespace OHOS {
namespace MMI {

std::shared_ptr<IPreferenceManager> IPreferenceManager::instance_;
std::mutex IPreferenceManager::mutex_;

std::shared_ptr<IPreferenceManager> IPreferenceManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = PreferencesManagerMock::GetInstance();
        }
    }
    return instance_;
}

std::shared_ptr<PreferencesManagerMock> PreferencesManagerMock::instance_;
std::mutex PreferencesManagerMock::mutex_;

std::shared_ptr<PreferencesManagerMock> PreferencesManagerMock::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<PreferencesManagerMock>();
        }
    }
    return instance_;
}
} // namespace MMI
} // namespace OHOS