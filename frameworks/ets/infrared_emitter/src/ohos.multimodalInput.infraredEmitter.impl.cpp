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
    COMMON_UNSUPPORTED_IR_EMITTER = 3900011,
};
using TaiheInfraredFrequency = ::ohos::multimodalInput::infraredEmitter::InfraredFrequency;
static TaiheInfraredFrequency InfraredFrequencyToAni(OHOS::MMI::InfraredFrequency const & value)
{
    TaiheInfraredFrequency frequency = {};
    frequency.max = value.max_;
    frequency.min = value.min_;
    return frequency;
}

std::string HandleError(int32_t ret, int32_t &errorCode)
{
    std::string result = "";
    if (ret == RET_OK) {
        errorCode = RET_OK;
        return result;
    }
    errorCode = std::abs(ret);
    switch (errorCode) {
        case COMMON_USE_SYSAPI_ERROR:
            result = "Permission denied. Non-system application called system api.";
            break;
        case COMMON_PERMISSION_CHECK_ERROR:
            result = "Permission denied. Need ohos.permission.MANAGE_INPUT_INFRARED_EMITTER";
            break;
        case INPUT_DEVICE_NOT_SUPPORTED:
            result = "Capability not supported. Failed to call the API due to limited device capabilities.";
            break;
        default:
            result = "Parameter error.";
            break;
    }
    return result;
}

void TransmitInfrared(int64_t infraredFrequency, ::taihe::array_view<int64_t> pattern)
{
    CALL_DEBUG_ENTER;
    std::vector<int64_t> vecPattern;
    if (infraredFrequency <= 0) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR,
            "Parameter error.value of infraredFrequency must be greater than 0");
        return;
    }
    for (auto it = pattern.begin(); it != pattern.end(); ++it) {
        if (*it <= 0) {
            taihe::set_business_error(COMMON_PARAMETER_ERROR,
                "Parameter error.The element of pattern must be positive.");
            return;
        }
        vecPattern.push_back(*it);
    }
    if (vecPattern.size() <= 0 || vecPattern.size() > MAX_NUMBER_ARRAY_ELEMENT) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR,
            "Parameter error.The number of pattern elements is incorrect.");
        return;
    }
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->TransmitInfrared(infraredFrequency, vecPattern);
    if (ret != RET_OK) {
        int32_t errCode = 0;
        auto errMsg = HandleError(ret, errCode);
        MMI_HILOGE("errMsg:%{public}s,ret:%{public}d, errCode=%{public}d", errMsg.c_str(), ret, errCode);
        taihe::set_business_error(errCode, errMsg);
        return;
    }
}

::taihe::array<TaiheInfraredFrequency> GetInfraredFrequencies()
{
    CALL_DEBUG_ENTER;
    std::vector<OHOS::MMI::InfraredFrequency> frequencies;
    std::vector<TaiheInfraredFrequency> result;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetInfraredFrequencies(frequencies);
    if (ret == COMMON_UNSUPPORTED_IR_EMITTER) {
        TaiheInfraredFrequency frequency = {};
        frequency.max = 0;
        frequency.min = 0;
        result.push_back(frequency);
        return ::taihe::array<::TaiheInfraredFrequency>(result);
    } else if (ret != RET_OK) {
        int32_t errCode = 0;
        auto errMsg = HandleError(ret, errCode);
        MMI_HILOGE("errMsg:%{public}s,ret:%{public}d, errCode=%{public}d", errMsg.c_str(), ret, errCode);
        taihe::set_business_error(errCode, errMsg);
        return ::taihe::array<TaiheInfraredFrequency>(result);
    }

    for (size_t i = 0; i < std::size(frequencies); ++i) {
        auto taiheObj = InfraredFrequencyToAni(frequencies.at(i));
        result.push_back(taiheObj);
    }
    return ::taihe::array<::TaiheInfraredFrequency>(result);
}

bool HasIrEmitterAsync()
{
    bool hasIrEmitter = false;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->HasIrEmitter(hasIrEmitter);
    if (ret != RET_OK) {
        int32_t errCode = 0;
        auto errMsg = HandleError(ret, errCode);
        MMI_HILOGE("errMsg:%{public}s,ret:%{public}d, errCode=%{public}d", errMsg.c_str(), ret, errCode);
        taihe::set_business_error(errCode, errMsg);
        return false;
    }
    return hasIrEmitter;
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_TransmitInfrared(TransmitInfrared);
TH_EXPORT_CPP_API_GetInfraredFrequencies(GetInfraredFrequencies);
TH_EXPORT_CPP_API_HasIrEmitterAsync(HasIrEmitterAsync);
// NOLINTEND
