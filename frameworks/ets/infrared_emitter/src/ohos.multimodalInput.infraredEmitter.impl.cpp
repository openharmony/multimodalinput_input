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
    int32_t size = static_cast<int32_t>(pattern.size());
    std::vector<int64_t> vecPattern(pattern.begin(), pattern.end());

    std::string context = "infraredFrequency:" +
        std::to_string(infraredFrequency) + "\n;" + "; size=" + std::to_string(size) + ";";
    for (int32_t i = 0; i < size; i++) {
        context = context + std::to_string(i) + ": pattern: " + std::to_string(pattern[i]) + ";";
    }
    MMI_HILOGD("ohos.multimodalInput.infraredEmitter.TransmitInfrared para size:%{public}s", context.c_str());
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
                "ohos.multimodalInput.infraredEmitter.TransmitInfrared requst error. returnCode:%{public}d", ret);
        }
    }
}

::taihe::array<::ohos::multimodalInput::infraredEmitter::InfraredFrequency> GetInfraredFrequencies()
{
    CALL_DEBUG_ENTER;
    std::vector<OHOS::MMI::InfraredFrequency> requencys;
    int32_t ret = OHOS::MMI::InputManager::GetInstance()->GetInfraredFrequencies(requencys);
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
                "ohos.multimodalInput.infraredEmitter.TransmitInfrared requst error. returnCode:%{public}d", ret);
        }
        return ::taihe::array<::ohos::multimodalInput::infraredEmitter::InfraredFrequency>(nullptr, 0);
    }
    ::ohos::multimodalInput::infraredEmitter::InfraredFrequency aniempty = {};
    std::vector<::ohos::multimodalInput::infraredEmitter::InfraredFrequency> resultTemp(requencys.size(), aniempty);
    std::transform(requencys.begin(), requencys.end(), resultTemp.begin(),
        [](OHOS::MMI::InfraredFrequency c) {
            ::ohos::multimodalInput::infraredEmitter::InfraredFrequency anitemp = InfraredFrequencyToAni(c);
            return anitemp;
    });
    return ::taihe::array<::ohos::multimodalInput::infraredEmitter::InfraredFrequency>(::taihe::copy_data_t{},
        resultTemp.data(), resultTemp.size());
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_TransmitInfrared(TransmitInfrared);
TH_EXPORT_CPP_API_GetInfraredFrequencies(GetInfraredFrequencies);
// NOLINTEND
