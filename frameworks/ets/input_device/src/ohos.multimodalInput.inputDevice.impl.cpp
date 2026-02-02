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
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>

#include "ani_common.h"
#include "input_device.h"
#include "ohos.multimodalInput.inputDevice.impl.h"
#include "ohos.multimodalInput.keyCode.impl.h"
#include "taihe_event.h"
#include "taihe_input_device_utils.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TaiheInputDeviceImpl"

using namespace taihe;
using namespace OHOS::MMI;
using namespace ohos::multimodalInput::inputDevice;
using TaiheKeyCode = ohos::multimodalInput::keyCode::KeyCode;
using TaiheFunctionKey = ohos::multimodalInput::inputDevice::FunctionKey;
using TaiheKeyboardType = ohos::multimodalInput::inputDevice::KeyboardType;
using InputDevice_t = OHOS::MMI::InputDevice;
using AxisInfo_t = OHOS::MMI::InputDevice::AxisInfo;
using TaiheError_t = OHOS::MMI::TaiheError;
using InputManager_t = OHOS::MMI::InputManager;

namespace {
constexpr uint32_t MIN_N_SIZE { 1 };
constexpr uint32_t MAX_N_SIZE { 5 };
constexpr int32_t MIN_KEY_REPEAT_DELAY { 300 };
constexpr int32_t MAX_KEY_REPEAT_DELAY { 1000 };
constexpr int32_t MIN_KEY_REPEAT_RATE { 36 };
constexpr int32_t MAX_KEY_REPEAT_RATE { 100 };
constexpr int32_t REQUEST_CALLBACK_OVERTIME { 100 };
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

InputDeviceData GetDeviceAsync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputDevice_t> _device = std::make_shared<InputDevice_t>();
    auto callback = [&_device](std::shared_ptr<InputDevice_t> device) {
        _device = device;
    };
    int32_t ret = InputManager_t::GetInstance()->GetDevice(deviceId, callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
            codeMsg.msg = "Unknown error";
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get device, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        std::shared_ptr<InputDevice> errDevice = nullptr;
        return TaiheInputDeviceUtils::ConverterInputDevice(errDevice);
    }
    return TaiheInputDeviceUtils::ConverterInputDevice(_device);
}

InputDeviceData GetDeviceInfoSync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputDevice_t> _device = std::make_shared<InputDevice_t>();
    auto callback = [&_device](std::shared_ptr<InputDevice_t> device) { _device = device; };
    int32_t ret = InputManager_t::GetInstance()->GetDevice(deviceId, callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Invalid input device id");
            return TaiheInputDeviceUtils::ConverterInputDevice(_device);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get device info, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        return TaiheInputDeviceUtils::ConverterInputDevice(_device);
    }
    return TaiheInputDeviceUtils::ConverterInputDevice(_device);
}

InputDeviceData GetDeviceInfoAsync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    return GetDeviceInfoSync(deviceId);
}

::taihe::array<bool> SupportKeysSync(int32_t deviceId, taihe::array_view<TaiheKeyCode> keys)
{
    CALL_DEBUG_ENTER;
    uint32_t size = keys.size();
    if (size < MIN_N_SIZE || size > MAX_N_SIZE) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "size range error");
        return ::taihe::array<bool>(nullptr, 0);
    }
    std::vector<bool> result {};
    auto callback = [&result] (std::vector<bool> &isSupported) { result = isSupported; };
    std::vector<int32_t> keyCodes;
    for (uint32_t i = 0; i < size; i++) {
        keyCodes.push_back(static_cast<int32_t>(keys[i]));
    }
    int32_t ret = InputManager_t::GetInstance()->SupportKeys(deviceId, keyCodes, callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
            return ::taihe::array<bool>(nullptr, 0);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to support keys sync, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        return ::taihe::array<bool>(nullptr, 0);
    }
    uint32_t arrayLength = result.size();
    ::taihe::array<bool> res(arrayLength);
    for (uint32_t i = 0; i < arrayLength; i++) {
        res[i] = result[i];
    }
    return res;
}

::taihe::array<bool> SupportKeysAsync(int32_t deviceId, taihe::array_view<TaiheKeyCode> keys)
{
    CALL_DEBUG_ENTER;
    return SupportKeysSync(deviceId, keys);
}

void SetKeyboardRepeatDelayAsync(int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (!TaiheInputDeviceUtils::IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return;
    }
    if (delay < MIN_KEY_REPEAT_DELAY) {
        delay = MIN_KEY_REPEAT_DELAY;
    } else if (delay > MAX_KEY_REPEAT_DELAY) {
        delay = MAX_KEY_REPEAT_DELAY;
    }
    int32_t ret = InputManager_t::GetInstance()->SetKeyboardRepeatDelay(delay);
    if (ret != RET_OK) {
        MMI_HILOGE("ret:%{public}d", ret);
        if (abs(ret) == COMMON_USE_SYSAPI_ERROR) {
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
            return;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error");
        return;
    }
}

int32_t GetKeyboardRepeatDelayAsync()
{
    CALL_DEBUG_ENTER;
    int32_t delay = -1;
    if (!TaiheInputDeviceUtils::IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return delay;
    }
    auto callback = [&delay] (int32_t tmpDelay) { delay = tmpDelay; };
    int32_t ret = InputManager_t::GetInstance()->GetKeyboardRepeatDelay(callback);
    if (ret != RET_OK) {
        MMI_HILOGE("ret:%{public}d,delay:%{public}d", ret, delay);
        if (abs(ret) == COMMON_USE_SYSAPI_ERROR) {
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
            return delay;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error");
    }
    return delay;
}

void SetKeyboardRepeatRateAsync(int32_t rate)
{
    CALL_DEBUG_ENTER;
    if (!TaiheInputDeviceUtils::IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return;
    }
    if (rate < MIN_KEY_REPEAT_RATE) {
        rate = MIN_KEY_REPEAT_RATE;
    } else if (rate > MAX_KEY_REPEAT_RATE) {
        rate = MAX_KEY_REPEAT_RATE;
    }
    int32_t ret = InputManager_t::GetInstance()->SetKeyboardRepeatRate(rate);
    if (ret != RET_OK) {
        MMI_HILOGE("ret:%{public}d", ret);
        if (abs(ret) == COMMON_USE_SYSAPI_ERROR) {
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
            return;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error");
    }
}

int32_t GetKeyboardRepeatRateAsync()
{
    CALL_DEBUG_ENTER;
    int32_t rate = -1;
    if (!TaiheInputDeviceUtils::IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return rate;
    }
    auto callback = [&rate] (int32_t tmpRate) { rate = tmpRate; };
    int32_t ret = InputManager_t::GetInstance()->GetKeyboardRepeatRate(callback);
    if (ret != RET_OK) {
        MMI_HILOGE("ret:%{public}d, rate:%{public}d", ret, rate);
        if (abs(ret) == COMMON_USE_SYSAPI_ERROR) {
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
            return rate;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error");
    }
    return rate;
}

int64_t GetIntervalSinceLastInputAsync()
{
    CALL_DEBUG_ENTER;
    int64_t timeInterval = 0;
    int32_t ret = InputManager_t::GetInstance()->GetIntervalSinceLastInput(timeInterval);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get interval since last input, code:%{public}d message: %{public}s",
            ret, codeMsg.msg.c_str());
    }
    return timeInterval;
}

void SetFunctionKeyEnabledAsync(TaiheFunctionKey functionKey, bool enabled)
{
    CALL_DEBUG_ENTER;
    if (functionKey != OHOS::MMI::FunctionKey::FUNCTION_KEY_CAPSLOCK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(COMMON_PARAMETER_ERROR, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", COMMON_PARAMETER_ERROR);
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, codeMsg.msg);
        MMI_HILOGE("First parameter value error");
        return;
    }
    int32_t ret = InputManager_t::GetInstance()->SetFunctionKeyState(functionKey, enabled);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to set functionKey state, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
    }
}

bool IsFunctionKeyEnabledAsync(TaiheFunctionKey functionKey)
{
    CALL_DEBUG_ENTER;
    if (functionKey != OHOS::MMI::FunctionKey::FUNCTION_KEY_CAPSLOCK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(COMMON_PARAMETER_ERROR, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", COMMON_PARAMETER_ERROR);
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error. Unknown error!");
            return false;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, codeMsg.msg);
        MMI_HILOGE("First parameter value error: %{public}s", codeMsg.msg.c_str());
        return false;
    }
    bool resultState = false;
    int32_t ret = InputManager_t::GetInstance()->GetFunctionKeyState(functionKey, resultState);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.Unknown error!");
            return resultState;
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get functionKey state, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        return resultState;
    }
    return resultState;
}

void SetInputDeviceEnableSyncImpl(int32_t deviceId, bool enabled)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<std::mutex> mtx = std::make_shared<std::mutex>();
    std::shared_ptr<std::condition_variable> cv = std::make_shared<std::condition_variable>();
    int32_t cbCode = RET_ERR;
    std::function<void(int32_t)> callback = [&cbCode, mtx, cv](int32_t errcode) {
        CALL_DEBUG_ENTER;
        std::unique_lock<std::mutex> lck(*mtx);
        cbCode = errcode;
        MMI_HILOGI("Callback exec,:%{public}d", cbCode);
        cv->notify_all();
    };
    int32_t ret = InputManager_t::GetInstance()->SetInputDeviceEnabled(deviceId, enabled, callback);
    MMI_HILOGI("ret code:%{public}d", ret);
    if (ret != RET_OK) {
        if (abs(ret) == ERROR_NOT_SYSAPI) {
            taihe::set_business_error(ERROR_NOT_SYSAPI, "Permission denied, non-system application called system api.");
        } else if (ret == ERROR_NO_PERMISSION) {
            taihe::set_business_error(-ret, "Permission denied.");
        } else {
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.Unknown error!");
        }
        return;
    }
    MMI_HILOGI("begin wait_for!!");
    std::unique_lock<std::mutex> lck(*mtx);
    auto status = cv->wait_for(lck, std::chrono::milliseconds(REQUEST_CALLBACK_OVERTIME));
    MMI_HILOGI("wait_for end status:%{public}d!!", static_cast<int32_t>(status));
    if (status == std::cv_status::timeout) {
        MMI_HILOGE("callback overtime!!");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.Overtime!");
        return;
    }
    MMI_HILOGI("Wait_for end return,ret:%{public}d", cbCode);
    if (cbCode != RET_OK) {
        if (cbCode == COMMON_DEVICE_NOT_EXIST) {
            taihe::set_business_error(COMMON_DEVICE_NOT_EXIST, "The specified device does not exist.");
            return;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.Service return error!");
    }
}

TaiheKeyboardType GetKeyboardTypeSync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    int32_t type = 0;
    auto callback = [&type] (int32_t keyboardType) {  type = keyboardType; };
    int32_t ret = InputManager_t::GetInstance()->GetKeyboardType(deviceId, callback);
    if (ret != RET_OK) {
        MMI_HILOGE("failed to get keyborad type,ret:%{public}d", ret);
        set_business_error(COMMON_PARAMETER_ERROR, "Invalid input device id");
        return TaiheKeyboardType::key_t::UNKNOWN;
    }
    TaiheKeyboardType kType =
        static_cast<TaiheKeyboardType::key_t>(type);
    return kType;
}

TaiheKeyboardType GetKeyboardTypeSyncWrapper(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    return GetKeyboardTypeSync(deviceId);
}

void onKeyImpl(::taihe::callback_view<void(::ohos::multimodalInput::inputDevice::DeviceListener const& info)> f,
    uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    TaiheEvent::GetInstance()->RegisterListener(CHANGED_TYPE, std::forward<callbackTypes>(f), opq);
}

void offKeyImpl(::taihe::optional_view<uintptr_t> opq)
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
TH_EXPORT_CPP_API_GetDeviceAsync(GetDeviceAsync);
TH_EXPORT_CPP_API_GetDeviceInfoSync(GetDeviceInfoSync);
TH_EXPORT_CPP_API_GetDeviceInfoAsync(GetDeviceInfoAsync);
TH_EXPORT_CPP_API_SupportKeysSync(SupportKeysSync);
TH_EXPORT_CPP_API_SupportKeysAsync(SupportKeysAsync);
TH_EXPORT_CPP_API_SetKeyboardRepeatDelayAsync(SetKeyboardRepeatDelayAsync);
TH_EXPORT_CPP_API_GetKeyboardRepeatDelayAsync(GetKeyboardRepeatDelayAsync);
TH_EXPORT_CPP_API_SetKeyboardRepeatRateAsync(SetKeyboardRepeatRateAsync);
TH_EXPORT_CPP_API_GetKeyboardRepeatRateAsync(GetKeyboardRepeatRateAsync);
TH_EXPORT_CPP_API_GetIntervalSinceLastInputAsync(GetIntervalSinceLastInputAsync);
TH_EXPORT_CPP_API_SetFunctionKeyEnabledAsync(SetFunctionKeyEnabledAsync);
TH_EXPORT_CPP_API_IsFunctionKeyEnabledAsync(IsFunctionKeyEnabledAsync);
TH_EXPORT_CPP_API_SetInputDeviceEnableSyncImpl(SetInputDeviceEnableSyncImpl);
TH_EXPORT_CPP_API_GetKeyboardTypeSyncWrapper(GetKeyboardTypeSyncWrapper);
TH_EXPORT_CPP_API_GetKeyboardTypeSync(GetKeyboardTypeSync);
TH_EXPORT_CPP_API_onKeyImpl(onKeyImpl);
TH_EXPORT_CPP_API_offKeyImpl(offKeyImpl);
// NOLINTEND
