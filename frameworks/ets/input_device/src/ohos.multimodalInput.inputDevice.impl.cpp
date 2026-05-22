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

#include "ani_common.h"
#include "input_device.h"
#include "mmi_api_metrics_histograms.h"
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
const std::string CHANGED_TYPE = "change";

::taihe::array<int32_t> GetDeviceIdsAsync()
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.getDeviceList.Call", true);
    std::vector<int32_t> _ids;
    auto callback = [&_ids] (std::vector<int32_t>& ids) { _ids = ids; };
    int32_t ret = InputManager_t::GetInstance()->GetDeviceIds(callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getDeviceList.Error", ret);
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
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.getDevice.Call", true);
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
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getDevice.Error", ret);
        MMI_HILOGE("failed to get device, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        std::shared_ptr<InputDevice> errDevice = nullptr;
        return TaiheInputDeviceUtils::ConverterInputDevice(errDevice);
    }
    return TaiheInputDeviceUtils::ConverterInputDevice(_device);
}

static InputDeviceData GetDeviceInfo(int32_t deviceId, std::function<void(int32_t)> histogramError)
{
    std::shared_ptr<InputDevice_t> _device = std::make_shared<InputDevice_t>();
    auto callback = [&_device](std::shared_ptr<InputDevice_t> device) { _device = device; };
    int32_t ret = InputManager_t::GetInstance()->GetDevice(deviceId, callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Invalid input device id");
            histogramError(COMMON_PARAMETER_ERROR);
            return TaiheInputDeviceUtils::ConverterInputDevice(_device);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        histogramError(ret);
        MMI_HILOGE("failed to get device info, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        return TaiheInputDeviceUtils::ConverterInputDevice(_device);
    }
    return TaiheInputDeviceUtils::ConverterInputDevice(_device);
}

InputDeviceData GetDeviceInfoSync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.getDeviceInfoSync.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getDeviceInfoSync.Error", errorCode);
    };
    return GetDeviceInfo(deviceId, histogramError);
}

InputDeviceData GetDeviceInfoAsync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.getDeviceInfo.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getDeviceInfo.Error", errorCode);
    };
    return GetDeviceInfo(deviceId, histogramError);
}

static ::taihe::array<bool> SupportKeys(int32_t deviceId, taihe::array_view<TaiheKeyCode> keys,
    std::function<void(int32_t)> histogramError)
{
    uint32_t size = keys.size();
    if (size < MIN_N_SIZE || size > MAX_N_SIZE) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "size range error");
        histogramError(COMMON_PARAMETER_ERROR);
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
            histogramError(COMMON_PARAMETER_ERROR);
            return ::taihe::array<bool>(nullptr, 0);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        histogramError(ret);
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

::taihe::array<bool> SupportKeysSync(int32_t deviceId, taihe::array_view<TaiheKeyCode> keys)
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.supportKeysSync.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.supportKeysSync.Error", errorCode);
    };
    return SupportKeys(deviceId, keys, histogramError);
}

::taihe::array<bool> SupportKeysAsync(int32_t deviceId, taihe::array_view<TaiheKeyCode> keys)
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.supportKeys.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.supportKeys.Error", errorCode);
    };
    return SupportKeys(deviceId, keys, histogramError);
}

void SetKeyboardRepeatDelayAsync(int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (!TaiheInputDeviceUtils::IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return;
    }
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.setKeyboardRepeatDelay.Call", true);
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
            MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setKeyboardRepeatDelay.Error", COMMON_USE_SYSAPI_ERROR);
            return;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error");
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setKeyboardRepeatDelay.Error", COMMON_PARAMETER_ERROR);
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
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.getKeyboardRepeatDelay.Call", true);
    auto callback = [&delay] (int32_t tmpDelay) { delay = tmpDelay; };
    int32_t ret = InputManager_t::GetInstance()->GetKeyboardRepeatDelay(callback);
    if (ret != RET_OK) {
        MMI_HILOGE("ret:%{public}d,delay:%{public}d", ret, delay);
        if (abs(ret) == COMMON_USE_SYSAPI_ERROR) {
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
            MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getKeyboardRepeatDelay.Error", COMMON_USE_SYSAPI_ERROR);
            return delay;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error");
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getKeyboardRepeatDelay.Error", COMMON_PARAMETER_ERROR);
    }
    return delay;
}

void SetKeyboardRepeatRateAsync(int32_t rate)
{
    CALL_DEBUG_ENTER;
    if (!TaiheInputDeviceUtils::IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setKeyboardRepeatRate.Error", COMMON_USE_SYSAPI_ERROR);
        return;
    }
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.setKeyboardRepeatRate.Call", true);
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
            MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setKeyboardRepeatRate.Error", COMMON_USE_SYSAPI_ERROR);
            return;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error");
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setKeyboardRepeatRate.Error", COMMON_PARAMETER_ERROR);
    }
}

int32_t GetKeyboardRepeatRateAsync()
{
    CALL_DEBUG_ENTER;
    int32_t rate = -1;
    if (!TaiheInputDeviceUtils::IsSystemApp()) {
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getKeyboardRepeatRate.Error", COMMON_USE_SYSAPI_ERROR);
        return rate;
    }
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.getKeyboardRepeatRate.Call", true);
    auto callback = [&rate] (int32_t tmpRate) { rate = tmpRate; };
    int32_t ret = InputManager_t::GetInstance()->GetKeyboardRepeatRate(callback);
    if (ret != RET_OK) {
        MMI_HILOGE("ret:%{public}d, rate:%{public}d", ret, rate);
        if (abs(ret) == COMMON_USE_SYSAPI_ERROR) {
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
            MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getKeyboardRepeatRate.Error", COMMON_USE_SYSAPI_ERROR);
            return rate;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error");
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getKeyboardRepeatRate.Error", COMMON_PARAMETER_ERROR);
    }
    return rate;
}

int64_t GetIntervalSinceLastInputAsync()
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.getIntervalSinceLastInput.Call", true);
    int64_t timeInterval = 0;
    int32_t ret = InputManager_t::GetInstance()->GetIntervalSinceLastInput(timeInterval);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getIntervalSinceLastInput.Error", ret);
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get interval since last input, code:%{public}d message: %{public}s",
            ret, codeMsg.msg.c_str());
    }
    return timeInterval;
}

void SetFunctionKeyEnabledAsync(TaiheFunctionKey functionKey, bool enabled)
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.setFunctionKeyEnabled.Call", true);
    if (functionKey != OHOS::MMI::FunctionKey::FUNCTION_KEY_CAPSLOCK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(COMMON_PARAMETER_ERROR, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", COMMON_PARAMETER_ERROR);
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, codeMsg.msg);
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setFunctionKeyEnabled.Error", COMMON_PARAMETER_ERROR);
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
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setFunctionKeyEnabled.Error", ret);
        MMI_HILOGE("failed to set functionKey state, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
    }
}

bool IsFunctionKeyEnabledAsync(TaiheFunctionKey functionKey)
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.isFunctionKeyEnabled.Call", true);
    if (functionKey != OHOS::MMI::FunctionKey::FUNCTION_KEY_CAPSLOCK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(COMMON_PARAMETER_ERROR, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", COMMON_PARAMETER_ERROR);
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error. Unknown error!");
            MMI_HISTOGRAM_ERROR("InputKit.inputDevice.isFunctionKeyEnabled.Error", COMMON_PARAMETER_ERROR);
            return false;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, codeMsg.msg);
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.isFunctionKeyEnabled.Error", COMMON_PARAMETER_ERROR);
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
            MMI_HISTOGRAM_ERROR("InputKit.inputDevice.isFunctionKeyEnabled.Error", COMMON_PARAMETER_ERROR);
            return resultState;
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get functionKey state, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.isFunctionKeyEnabled.Error", ret);
        return resultState;
    }
    return resultState;
}

bool ANIPromiseVoidCallback(ani_env* env, ani_resolver deferred, int32_t errCode)
{
    CALL_DEBUG_ENTER;
    ani_status status = ANI_OK;
    if (errCode != RET_OK) {
        TaiheError  codeMsg;
        if (!TaiheConverter::GetApiError(errCode, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", errCode);
            errCode = COMMON_PARAMETER_ERROR;
            codeMsg.msg = "Parameter error.unknown error";
        }
        auto callResult = TaiheInputDeviceUtils::CreateBusinessError(env, static_cast<ani_int>(errCode), codeMsg.msg);
        if (callResult == nullptr) {
            MMI_HILOGE("The callResult is nullptr");
            return false;
        }
        if ((status = env->PromiseResolver_Reject(deferred, static_cast<ani_error>(callResult))) != ANI_OK) {
            MMI_HILOGE("create promise object failed, status = %{public}d", status);
            return false;
        }
        return true;
    }
    ani_ref promiseResult;
    if ((status = env->GetUndefined(&promiseResult)) != ANI_OK) {
        MMI_HILOGE("get undefined value failed, status = %{public}d", status);
        return false;
    }
    if ((status = env->PromiseResolver_Resolve(deferred, promiseResult)) != ANI_OK) {
        MMI_HILOGE("PromiseResolver_Resolve failed, status = %{public}d", status);
        return false;
    }
    return true;
}

uintptr_t SetInputDeviceEnablePromise(int32_t deviceId, bool enabled)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.setInputDeviceEnabled.Call", true);
    if (deviceId < 0) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.Invalid deviceId!");
        MMI_HILOGE("Invalid deviceId");
        return 0;
    }
    ani_env *env = taihe::get_env();
    if (!env) {
        MMI_HILOGE("env is null");
        return 0;
    }
    ani_status status = ANI_OK;
    ani_object promise;
    ani_resolver deferred = nullptr;
    if ((status = env->Promise_New(&deferred, &promise)) != ANI_OK) {
        MMI_HILOGE("create promise object failed, status = %{public}d", status);
        return reinterpret_cast<uintptr_t>(promise);
    }
    std::function<void(int32_t)> callback = [env, deferred](int32_t errcode) {
        CALL_DEBUG_ENTER;
        ani_env* etsEnv = env;
        ANIPromiseVoidCallback(etsEnv, deferred, errcode);
    };
    int32_t ret = InputManager_t::GetInstance()->SetInputDeviceEnabled(deviceId, enabled, callback);
    MMI_HILOGI("ret code:%{public}d", ret);
    if (ret != RET_OK) {
        if (abs(ret) == ERROR_NOT_SYSAPI) {
            taihe::set_business_error(ERROR_NOT_SYSAPI, "Permission denied, non-system application called system api.");
            MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setInputDeviceEnabled.Error", ERROR_NOT_SYSAPI);
        } else if (ret == ERROR_NO_PERMISSION) {
            taihe::set_business_error(-ret, "Permission denied.");
            MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setInputDeviceEnabled.Error", ERROR_NO_PERMISSION);
        } else {
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.Unknown error!");
            MMI_HISTOGRAM_ERROR("InputKit.inputDevice.setInputDeviceEnabled.Error", COMMON_PARAMETER_ERROR);
        }
        return 0;
    }
    return reinterpret_cast<uintptr_t>(promise);
}

static TaiheKeyboardType GetKeyboardType(int32_t deviceId, std::function<void(int32_t)> histogramError)
{
    CALL_DEBUG_ENTER;
    int32_t type = 0;
    auto callback = [&type] (int32_t keyboardType) {  type = keyboardType; };
    int32_t ret = InputManager_t::GetInstance()->GetKeyboardType(deviceId, callback);
    if (ret != RET_OK) {
        MMI_HILOGE("failed to get keyborad type,ret:%{public}d", ret);
        set_business_error(COMMON_PARAMETER_ERROR, "Invalid input device id");
        histogramError(COMMON_PARAMETER_ERROR);
        return TaiheKeyboardType::key_t::UNKNOWN;
    }
    TaiheKeyboardType kType =
        static_cast<TaiheKeyboardType::key_t>(type);
    return kType;
}

TaiheKeyboardType GetKeyboardTypeSync(int32_t deviceId)
{
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.getKeyboardTypeSync.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getKeyboardTypeSync.Error", errorCode);
    };
    return GetKeyboardType(deviceId, histogramError);
}

TaiheKeyboardType GetKeyboardTypeSyncWrapper(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.getKeyboardType.Call", true);
    auto histogramError = [](int32_t errorCode) {
        MMI_HISTOGRAM_ERROR("InputKit.inputDevice.getKeyboardType.Error", errorCode);
    };
    return GetKeyboardType(deviceId, histogramError);
}

void onKeyImpl(::taihe::callback_view<void(::ohos::multimodalInput::inputDevice::DeviceListener const& info)> f,
    uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.on_change.Call", true);
    TaiheEvent::GetInstance()->RegisterListener(CHANGED_TYPE, std::forward<callbackTypes>(f), opq);
}

void offKeyImpl(::taihe::optional_view<uintptr_t> opq)
{
    CALL_DEBUG_ENTER;
    MMI_HISTOGRAM_BOOLEAN("InputKit.inputDevice.off_change.Call", true);
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
TH_EXPORT_CPP_API_SetInputDeviceEnablePromise(SetInputDeviceEnablePromise);
TH_EXPORT_CPP_API_GetKeyboardTypeSyncWrapper(GetKeyboardTypeSyncWrapper);
TH_EXPORT_CPP_API_GetKeyboardTypeSync(GetKeyboardTypeSync);
TH_EXPORT_CPP_API_onKeyImpl(onKeyImpl);
TH_EXPORT_CPP_API_offKeyImpl(offKeyImpl);
// NOLINTEND
