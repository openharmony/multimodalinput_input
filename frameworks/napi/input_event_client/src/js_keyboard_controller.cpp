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

#include "js_keyboard_controller.h"

#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsKeyboardController"

namespace OHOS {
namespace MMI {

JsKeyboardController::JsKeyboardController()
{
    MMI_HILOGD("Creating JsKeyboardController");
    // Create the core implementation instance via InputManager
    impl_ = InputManager::GetInstance()->CreateKeyboardController();
    if (impl_ == nullptr) {
        MMI_HILOGE("Failed to create KeyboardControllerImpl");
    }
}

int32_t JsKeyboardController::PressKey(int32_t keyCode)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("KeyboardControllerImpl is null");
        return RET_ERR;
    }
    return impl_->PressKey(keyCode);
}

int32_t JsKeyboardController::ReleaseKey(int32_t keyCode)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("KeyboardControllerImpl is null");
        return RET_ERR;
    }
    return impl_->ReleaseKey(keyCode);
}

} // namespace MMI
} // namespace OHOS
