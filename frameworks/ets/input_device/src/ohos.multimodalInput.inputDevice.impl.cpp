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
    if (ret != OTHER_ERROR && ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get device, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        std::shared_ptr<InputDevice> errDevice = nullptr;
        return TaiheInputDeviceUtils::ConverterInputDevice(errDevice);
    }
    return TaiheInputDeviceUtils::ConverterInputDevice(_device);
}

InputDeviceData GetDeviceInfoAsync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputDevice_t> _device = std::make_shared<InputDevice_t>();
    auto callback = [&_device](std::shared_ptr<InputDevice_t> device) {
        _device = device;
    };
    int32_t ret = InputManager_t::GetInstance()->GetDevice(deviceId, callback);
    if (ret != RET_OK) {
        TaiheInputDeviceData result {};
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
            taihe::set_business_error(OTHER_ERROR, "Unknown error");
            return result;
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get device info, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        std::shared_ptr<InputDevice> errDevice = nullptr;
        return result;
    }
    return TaiheInputDeviceUtils::ConverterInputDevice(_device);
}

::taihe::array<bool> SupportKeysAsync(int32_t deviceId, taihe::array_view<TaiheKeyCode> keys)
{
    CALL_DEBUG_ENTER;
    uint32_t size = keys.size();
    if (size < MIN_N_SIZE || size > MAX_N_SIZE) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(COMMON_PARAMETER_ERROR, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", COMMON_PARAMETER_ERROR);
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, codeMsg.msg);
        return ::taihe::array<bool>(nullptr, 0);
    }
    std::vector<int32_t> keyCodes;
    keyCodes.resize(size);
    for (auto &key: keys) {
        auto value = TaiheKeyCodeConverter::GetKeyCodeByValue(KEY_CODE_TRANSFORMATION, key);
        keyCodes.push_back(static_cast<int32_t>(value));
    }
    std::vector<bool> _keystrokeAbility;
    auto callback = [&_keystrokeAbility] (std::vector<bool>& keystrokeAbility) {
        _keystrokeAbility = keystrokeAbility;
    };
    int32_t ret = InputManager_t::GetInstance()->SupportKeys(deviceId, keyCodes, callback);
    if (ret != OTHER_ERROR && ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to support keys, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        return ::taihe::array<bool>(nullptr, 0);
    }
    uint32_t arrayLength = _keystrokeAbility.size();
    ::taihe::array<bool> res(arrayLength);
    for (uint32_t i = 0; i < arrayLength; i++) {
        res[i] = _keystrokeAbility[i];
    }
    return res;
}

void SetKeyboardRepeatDelayAsync(int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (delay < MIN_KEY_REPEAT_DELAY) {
        delay = MIN_KEY_REPEAT_DELAY;
    } else if (delay > MAX_KEY_REPEAT_DELAY) {
        delay = MAX_KEY_REPEAT_DELAY;
    }
    int32_t ret = InputManager_t::GetInstance()->SetKeyboardRepeatDelay(delay);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to set keyboard repeat delay, code:%{public}d message: %{public}s",
            ret, codeMsg.msg.c_str());
        return;
    }
}

int32_t GetKeyboardRepeatDelayAsync()
{
    CALL_DEBUG_ENTER;
    int32_t delay = -1;
    auto callback = [&delay] (int32_t tmpDelay) { delay = tmpDelay; };
    int32_t ret = InputManager_t::GetInstance()->GetKeyboardRepeatDelay(callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get keyboard repeat delay, code:%{public}d message: %{public}s",
            ret, codeMsg.msg.c_str());
    }
    return delay;
}

void SetKeyboardRepeatRateAsync(int32_t rate)
{
    CALL_DEBUG_ENTER;
    if (rate < MIN_KEY_REPEAT_RATE) {
        rate = MIN_KEY_REPEAT_RATE;
    } else if (rate > MAX_KEY_REPEAT_RATE) {
        rate = MAX_KEY_REPEAT_RATE;
    }
    int32_t ret = InputManager_t::GetInstance()->SetKeyboardRepeatRate(rate);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to set keyboard repeat rate, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
    }
}

int32_t GetKeyboardRepeatRateAsync()
{
    CALL_DEBUG_ENTER;
    int32_t rate = -1;
    auto callback = [&rate] (int32_t tmpRate) { rate = tmpRate; };
    int32_t ret = InputManager_t::GetInstance()->GetKeyboardRepeatRate(callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to get keyboard repeat rate, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
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
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Unkonwn error!");
            return false;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, codeMsg.msg);
        MMI_HILOGE("First parameter value error");
        return false;
    }
    bool resultState = false;
    int32_t ret = InputManager_t::GetInstance()->GetFunctionKeyState(functionKey, resultState);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Unkonwn error!");
            return resultState;
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to set functionKey state, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
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
            return false;
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
    CALL_DEBUG_ENTER;
    if (deviceId < 0) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(COMMON_PARAMETER_ERROR, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", COMMON_PARAMETER_ERROR);
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Unkonwn error!");
            return 0;
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, codeMsg.msg);
        MMI_HILOGE("Invalid deviceId");
        return 0;
    }
    ani_env *env = taihe::get_env();
    CHKPR(env, 0);
    ani_status status = ANI_OK;
    ani_object promise;
    ani_resolver deferred = nullptr;
    if ((status = env->Promise_New(&deferred, &promise)) != ANI_OK) {
        MMI_HILOGE("create promise object failed, status = %{public}d", status);
        return reinterpret_cast<uintptr_t>(promise);
    }
    ani_vm *vm = nullptr;
    CHKFR(ANI_OK == env->GetVM(&vm), reinterpret_cast<uintptr_t>(promise), "env GetVM faild");
    std::function<void(int32_t)> callback = [vm, deferred](int32_t errcode) {
        CALL_DEBUG_ENTER;
        auto etsVm = vm;
        ani_env* etsEnv;
        ani_status aniResult = ANI_ERROR;
        ani_options aniArgs { 0, nullptr };
        aniResult = etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
        CHKFRV(ANI_OK == aniResult, "AttachCurrentThread error");
        ANIPromiseVoidCallback(etsEnv, deferred, errcode);
        aniResult = etsVm->DetachCurrentThread();
        CHKFRV(ANI_OK == aniResult, "DetachCurrentThread error");
    };
    int32_t ret = InputManager_t::GetInstance()->SetInputDeviceEnabled(deviceId, enabled, callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to set functionKey state, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
    }
    return reinterpret_cast<uintptr_t>(promise);
}

TaiheKeyboardType GetKeyboardTypeSync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    int32_t type = 0;
    auto callback = [&type] (int32_t keyboardType) {  type = keyboardType; };
    int32_t ret = InputManager_t::GetInstance()->GetKeyboardType(deviceId, callback);
    if (ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Unkonwn error!");
            return TaiheKeyboardType::key_t::UNKNOWN;
        }
        taihe::set_business_error(ret, codeMsg.msg);
        MMI_HILOGE("failed to set functionKey state, code:%{public}d message: %{public}s", ret, codeMsg.msg.c_str());
        return TaiheKeyboardType::key_t::UNKNOWN;
    }
    TaiheKeyboardType kType =
        static_cast<TaiheKeyboardType::key_t>(type);
    return kType;
}

TaiheKeyboardType GetKeyboardTypeAsync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    return GetKeyboardTypeSync(deviceId);
}

::taihe::array<bool> SupportKeysSync(int32_t deviceId, taihe::array_view<TaiheKeyCode> keys)
{
    CALL_DEBUG_ENTER;
    uint32_t size = keys.size();
    if (size < MIN_N_SIZE || size > MAX_N_SIZE) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(COMMON_PARAMETER_ERROR, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", COMMON_PARAMETER_ERROR);
        }
        taihe::set_business_error(COMMON_PARAMETER_ERROR, codeMsg.msg);
        MMI_HILOGE("param is invaild, code:%{public}d message: %{public}s",
            COMMON_PARAMETER_ERROR, codeMsg.msg.c_str());
        return ::taihe::array<bool>(nullptr, 0);
    }
    std::vector<bool> result {};
    auto callback = [&result] (std::vector<bool> &isSupported) { result = isSupported; };
    std::vector<int32_t> keyCodes;
    for (uint32_t i = 0; i < size; i++) {
        keyCodes.push_back(static_cast<int32_t>(keys[i]));
    }
    int32_t ret = InputManager_t::GetInstance()->SupportKeys(deviceId, keyCodes, callback);
    if (ret != OTHER_ERROR && ret != RET_OK) {
        TaiheError_t codeMsg;
        if (!TaiheConverter::GetApiError(ret, codeMsg)) {
            MMI_HILOGE("Error code %{public}d not found", ret);
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

InputDeviceData GetDeviceInfoSync(int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputDevice_t> _device = std::make_shared<InputDevice_t>();
    auto callback = [&_device](std::shared_ptr<InputDevice_t> device) { _device = device; };
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
TH_EXPORT_CPP_API_GetDeviceAsync(GetDeviceAsync);
TH_EXPORT_CPP_API_GetDeviceInfoAsync(GetDeviceInfoAsync);
TH_EXPORT_CPP_API_SupportKeysAsync(SupportKeysAsync);
TH_EXPORT_CPP_API_SetKeyboardRepeatDelayAsync(SetKeyboardRepeatDelayAsync);
TH_EXPORT_CPP_API_GetKeyboardRepeatDelayAsync(GetKeyboardRepeatDelayAsync);
TH_EXPORT_CPP_API_SetKeyboardRepeatRateAsync(SetKeyboardRepeatRateAsync);
TH_EXPORT_CPP_API_GetKeyboardRepeatRateAsync(GetKeyboardRepeatRateAsync);
TH_EXPORT_CPP_API_GetIntervalSinceLastInputAsync(GetIntervalSinceLastInputAsync);
TH_EXPORT_CPP_API_SetFunctionKeyEnabledAsync(SetFunctionKeyEnabledAsync);
TH_EXPORT_CPP_API_IsFunctionKeyEnabledAsync(IsFunctionKeyEnabledAsync);
TH_EXPORT_CPP_API_SetInputDeviceEnablePromise(SetInputDeviceEnablePromise);
TH_EXPORT_CPP_API_GetKeyboardTypeAsync(GetKeyboardTypeAsync);
TH_EXPORT_CPP_API_GetKeyboardTypeSync(GetKeyboardTypeSync);
TH_EXPORT_CPP_API_SupportKeysSync(SupportKeysSync);
TH_EXPORT_CPP_API_GetDeviceInfoSync(GetDeviceInfoSync);
TH_EXPORT_CPP_API_onKey(onKey);
TH_EXPORT_CPP_API_offKey(offKey);
// NOLINTEND
