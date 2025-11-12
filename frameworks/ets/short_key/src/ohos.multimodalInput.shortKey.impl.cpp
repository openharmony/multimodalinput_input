/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ohos.multimodalInput.shortKey.proj.hpp"
#include "ohos.multimodalInput.shortKey.impl.hpp"
#include "ohos.multimodalInput.shortKeyFunc.proj.hpp"
#include "ohos.multimodalInput.shortKeyFunc.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "ani_common.h"
#include "define_multimodal.h"
#include "input_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TaiHeShortKeyImpl"

using namespace taihe;
using namespace OHOS::MMI;
using namespace ohos::multimodalInput::shortKey;

namespace {
constexpr int32_t MAX_DELAY { 4000 };
constexpr int32_t MIN_DELAY { 0 };

void SetKeyDownDurationAsync(::taihe::string_view businessKey, int32_t delay)
{
    if (businessKey.empty()) {
        MMI_HILOGE("Invalid businessKey");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "businessId is invalid");
        return;
    }
    if (delay < MIN_DELAY || delay > MAX_DELAY) {
        MMI_HILOGE("Invalid delay");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Delay is invalid");
        return;
    }
    int32_t ret = InputManager::GetInstance()->SetKeyDownDuration(std::string(businessKey), delay);
    if (ret == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return;
    } else if (ret == COMMON_PARAMETER_ERROR) {
        MMI_HILOGE("Invalid param");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "param is invalid");
        return;
    }
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_SetKeyDownDurationAsync(SetKeyDownDurationAsync);
// NOLINTEND