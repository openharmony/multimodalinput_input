/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ohos.multimodalInput.inputDevice.proj.hpp"
#include "ohos.multimodalInput.inputDevice.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "input_device.h"
#include "define_multimodal.h"
#include "input_manager.h"
#include "ani_common.h"
#include <map>
#include <ani.h>
#include "ohos.multimodalInput.inputDevice.impl.h"
#include "taihe_event.h"
#include "taihe_input_device_utils.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TaiheInputDeviceImpl"

using namespace taihe;
using namespace OHOS::MMI;
using namespace ohos::multimodalInput::inputDevice;
using TaiheFunctionKey = ohos::multimodalInput::inputDevice::FunctionKey;
using TaiheKeyboardType = ohos::multimodalInput::inputDevice::KeyboardType;
using InputDevice_t = OHOS::MMI::InputDevice;
using AxisInfo_t = OHOS::MMI::InputDevice::AxisInfo;
using TaiheError_t = OHOS::MMI::TaiheError;
using InputManager_t = OHOS::MMI::InputManager;

namespace {
const std::string CHANGED_TYPE = "change";

::taihe::array<int32_t> GetDeviceIdsAsync()
{
    CALL_DEBUG_ENTER;
    std::vector<int32_t> _ids;
    auto callback = [&_ids] (std::vector<int32_t>& ids) { _ids = ids; };
    int32_t ret = InputManager_t::GetInstance()->GetDeviceIds(callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get Device ids, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        return ::taihe::array<int32_t>(nullptr, 0);
    }
    uint32_t size = _ids.size();
    ::taihe::array<int32_t> res(size);
    for (uint32_t i = 0; i < size; i++) {
        res[i] = _ids[i];
    }
    return res;
}

::ohos::multimodalInput::inputDevice::InputDeviceData GetDeviceInfoAsync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputDevice_t> _device = std::make_shared<InputDevice_t>();
    auto callback = [&_device](std::shared_ptr<InputDevice_t> device) {
        _device = device;
    };
    int32_t ret = InputManager_t::GetInstance()->GetDevice(deviceId, callback);
    if (ret != OTHER_ERROR && ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get device info, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        std::shared_ptr<InputDevice> errDevice = nullptr;
        return TaiheInputDeviceUtils::ConverterInputDevice(errDevice);
    }
    return TaiheInputDeviceUtils::ConverterInputDevice(_device);
}

void onKey(::taihe::callback_view<void(::ohos::multimodalInput::inputDevice::DeviceListener const& info)> f,
    uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    TaiheEvent::GetInstance()->RegisterListener(CHANGED_TYPE, std::forward<callbackTypes>(f), opq);
}

void offKey(::taihe::optional_view<uintptr_t> opq)
{
    CALL_DEBUG_ENTER;
    if (opq.has_value()) {
        TaiheEvent::GetInstance()->UnregisterListener(CHANGED_TYPE, opq.value());
    } else {
        TaiheEvent::GetInstance()->UnregisterAllListener(CHANGED_TYPE);
    }
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_GetDeviceIdsAsync(GetDeviceIdsAsync);
TH_EXPORT_CPP_API_GetDeviceInfoAsync(GetDeviceInfoAsync);
TH_EXPORT_CPP_API_onKey(onKey);
TH_EXPORT_CPP_API_offKey(offKey);
// NOLINTEND
