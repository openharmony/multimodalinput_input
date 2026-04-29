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

#include "js_touch_controller.h"

#include "input_manager.h"
#include "mmi_log.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsTouchController"

namespace OHOS {
namespace MMI {

JsTouchController::JsTouchController(std::shared_ptr<TouchControllerImpl> impl) : impl_(impl)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("TouchControllerImpl is null");
    }
}

int32_t JsTouchController::TouchDown(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("TouchControllerImpl is null");
        return CONTROLLER_INPUT_SERVICE_EXCEPTION;
    }
    return impl_->TouchDown(id, displayId, displayX, displayY);
}

int32_t JsTouchController::TouchMove(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("TouchControllerImpl is null");
        return CONTROLLER_INPUT_SERVICE_EXCEPTION;
    }
    return impl_->TouchMove(id, displayId, displayX, displayY);
}

int32_t JsTouchController::TouchUp(int32_t id, int32_t displayId, int32_t displayX, int32_t displayY)
{
    if (impl_ == nullptr) {
        MMI_HILOGE("TouchControllerImpl is null");
        return CONTROLLER_INPUT_SERVICE_EXCEPTION;
    }
    return impl_->TouchUp(id, displayId, displayX, displayY);
}

} // namespace MMI
} // namespace OHOS
