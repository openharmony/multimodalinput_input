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

#include "input_windows_manager_mock.h"

namespace OHOS {
namespace MMI {

std::shared_ptr<IInputWindowsManager> IInputWindowsManager::instance_;
std::mutex IInputWindowsManager::mutex_;

std::shared_ptr<IInputWindowsManager> IInputWindowsManager::GetInstance()
{
    return InputWindowsManagerMock::GetInstance();
}

std::shared_ptr<InputWindowsManagerMock> InputWindowsManagerMock::instance_;
std::mutex InputWindowsManagerMock::mutex_;

std::shared_ptr<InputWindowsManagerMock> InputWindowsManagerMock::GetInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<InputWindowsManagerMock>();
    }
    return instance_;
}

void InputWindowsManagerMock::ReleaseInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    instance_.reset();
}
} // namespace MMI
} // namespace OHOS
