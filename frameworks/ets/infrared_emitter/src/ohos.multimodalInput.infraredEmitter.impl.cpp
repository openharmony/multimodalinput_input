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

#include "ohos.multimodalInput.infraredEmitter.proj.hpp"
#include "ohos.multimodalInput.infraredEmitter.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "mmi_log.h"
#include "input_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "infrared_emitter_impl"

namespace {
constexpr int32_t MAX_NUMBER_ARRAY_ELEMENT { 1024 };
enum EtsErrorCode : int32_t {
    OTHER_ERROR = -1,
    COMMON_PERMISSION_CHECK_ERROR = 201,
    COMMON_USE_SYSAPI_ERROR = 202,
    COMMON_PARAMETER_ERROR = 401,
    INPUT_DEVICE_NOT_SUPPORTED = 801,
    COMMON_DEVICE_NOT_EXIST = 3900001,
    COMMON_KEYBOARD_DEVICE_NOT_EXIST = 3900002,
    COMMON_NON_INPUT_APPLICATION = 3900003,
    PRE_KEY_NOT_SUPPORTED = 4100001,
    INPUT_OCCUPIED_BY_SYSTEM = 4200002,
    INPUT_OCCUPIED_BY_OTHER = 4200003,
    ERROR_WINDOW_ID_PERMISSION_DENIED = 26500001,
};
using TaiheInfraredFrequency = ::ohos::multimodalInput::infraredEmitter::InfraredFrequency;
static TaiheInfraredFrequency InfraredFrequencyToAni(OHOS::MMI::InfraredFrequency const & value)
{
    TaiheInfraredFrequency frequency = {};
    frequency.max = value.max_;
    frequency.min = value.min_;
    return frequency;
}

void TransmitInfrared(int64_t infraredFrequency, ::taihe::array_view<int64_t> pattern)
{
    CALL_DEBUG_ENTER;
    std::vector<int64_t> vecPattern;
    if (infraredFrequency <= 0) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.value of infraredFrequencymust be greater than 0");
        return;
    }
    for (auto it = pattern.begin(); it != pattern.end(); ++it) {
        if (*it <= 0) {
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR,
                "Parameter error.The element of pattern must be positive.");
            return;
        }
        vecPattern.push_back(*it);
    }
    if (vecPattern.size() > MAX_NUMBER_ARRAY_ELEMENT) {
         taihe::set_business_error(COMMON_USE_SYSAPI_ERROR,
                "Parameter error.The size of pattern must be less than or equal 50.");
            return;
    }
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->TransmitInfrared(infraredFrequency, vecPattern);
    if (ret != RET_OK) {
        int32_t errorCode = std::abs(ret);
        if (errorCode == COMMON_USE_SYSAPI_ERROR) {
            MMI_HILOGE("Non system applications use system API");
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        } else if (errorCode == COMMON_PERMISSION_CHECK_ERROR) {
            MMI_HILOGE("Shield api need ohos.permission.INPUT_CONTROL_DISPATCHING");
            taihe::set_business_error(COMMON_PERMISSION_CHECK_ERROR,
                "Shield api need ohos.permission.INPUT_CONTROL_DISPATCHING");
        } else {
            MMI_HILOGE(
                "TransmitInfrared returnCode:%{public}d", ret);
        }
    }
}

::taihe::array<TaiheInfraredFrequency> GetInfraredFrequencies()
{
    CALL_DEBUG_ENTER;
    std::vector<OHOS::MMI::InfraredFrequency> frequencies;
    std::vector<TaiheInfraredFrequency> result;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetInfraredFrequencies(frequencies);
    if (ret != RET_OK) {
        int32_t errorCode = std::abs(ret);
        if (errorCode == COMMON_USE_SYSAPI_ERROR) {
            MMI_HILOGE("Non system applications use system API");
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        } else if (errorCode == COMMON_PERMISSION_CHECK_ERROR) {
            MMI_HILOGE("Shield api need ohos.permission.INPUT_CONTROL_DISPATCHING");
            taihe::set_business_error(COMMON_PERMISSION_CHECK_ERROR,
                "Shield api need ohos.permission.INPUT_CONTROL_DISPATCHING");
        } else {
            MMI_HILOGE(
                "GetInfraredFrequencies returnCode:%{public}d", ret);
        }
        return ::taihe::array<TaiheInfraredFrequency>(result);
    }

    for (size_t i = 0; i < std::size(frequencies); ++i) {
        auto taiheObj = InfraredFrequencyToAni(frequencies.at(i));
        result.push_back(taiheObj);
    }
    return ::taihe::array<::TaiheInfraredFrequency>(result);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_TransmitInfrared(TransmitInfrared);
TH_EXPORT_CPP_API_GetInfraredFrequencies(GetInfraredFrequencies);
// NOLINTEND
