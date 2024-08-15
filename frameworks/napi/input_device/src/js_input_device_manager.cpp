/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "js_input_device_manager.h"

#include "input_device_impl.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsInputDeviceManager"

namespace OHOS {
namespace MMI {
namespace {
std::mutex mutex_;
} // namespace
void JsInputDeviceManager::RegisterDevListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_DEBUG_ENTER;
    AddListener(env, type, handle);
}

void JsInputDeviceManager::UnregisterDevListener(napi_env env, const std::string &type, napi_value handle)
{
    CALL_DEBUG_ENTER;
    RemoveListener(env, type, handle);
}

napi_value JsInputDeviceManager::GetDeviceIds(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = [cb] (std::vector<int32_t> &ids) { return EmitJsIds(cb, ids); };
    InputManager::GetInstance()->GetDeviceIds(callback);
    return ret;
}

napi_value JsInputDeviceManager::GetDevice(napi_env env, int32_t id, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = [cb] (std::shared_ptr<InputDevice> device) { return EmitJsDev(cb, device); };
    InputManager::GetInstance()->GetDevice(id, callback);
    return ret;
}

napi_value JsInputDeviceManager::SupportKeys(napi_env env, int32_t id, std::vector<int32_t> &keyCodes,
    napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = [cb] (std::vector<bool> &keystrokeAbility) { return EmitSupportKeys(cb, keystrokeAbility); };
    int32_t napiCode = InputManager::GetInstance()->SupportKeys(id, keyCodes, callback);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return ret;
}

void JsInputDeviceManager::SupportKeysSyncCallback(napi_env env, napi_value* result, std::vector<bool> &isSupported)
{
    CALL_DEBUG_ENTER;
    napi_create_array(env, &(*result));
    for (uint i = 0; i < isSupported.size(); i++) {
        napi_value value;
        napi_get_boolean(env, isSupported[i], &value);
        napi_set_element(env, *result, i, value);
    }
}

napi_value JsInputDeviceManager::SupportKeysSync(napi_env env, int32_t id, std::vector<int32_t> &keyCodes)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    auto callback = [env, &result] (std::vector<bool> &isSupported) {
        return SupportKeysSyncCallback(env, &result, isSupported);
        };
    int32_t napiCode = InputManager::GetInstance()->SupportKeys(id, keyCodes, callback);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return result;
}

napi_value JsInputDeviceManager::GetKeyboardType(napi_env env, int32_t id, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = [cb] (int32_t keyboardType) { return EmitJsKeyboardType(cb, keyboardType); };
    int32_t napiCode = InputManager::GetInstance()->GetKeyboardType(id, callback);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return ret;
}

void JsInputDeviceManager::GetKeyboardTypeSyncCallback(napi_env env, napi_value* result, int32_t keyboardType)
{
    CALL_DEBUG_ENTER;
    auto status = napi_create_int32(env, keyboardType, &(*result));
    if (status != napi_ok) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Get keyboard type fail");
    }
}

napi_value JsInputDeviceManager::GetKeyboardTypeSync(napi_env env, int32_t id)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    auto callback = [env, &result] (int32_t keyboardType) {
        return GetKeyboardTypeSyncCallback(env, &result, keyboardType);
        };
    int32_t napiCode = InputManager::GetInstance()->GetKeyboardType(id, callback);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return result;
}

napi_value JsInputDeviceManager::GetDeviceList(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = [cb] (std::vector<int32_t> &ids) { return EmitJsIds(cb, ids); };
    InputManager::GetInstance()->GetDeviceIds(callback);
    return ret;
}

napi_value JsInputDeviceManager::GetDeviceInfo(napi_env env, int32_t id, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = [cb] (std::shared_ptr<InputDevice> inputDevice) { return EmitJsDev(cb, inputDevice); };
    int32_t napiCode = InputManager::GetInstance()->GetDevice(id, callback);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return ret;
}

void JsInputDeviceManager::GetDeviceInfoSyncCallback(napi_env env, napi_value* result, sptr<JsUtil::CallbackInfo> cb,
    std::shared_ptr<InputDevice> inputDevice)
{
    CALL_DEBUG_ENTER;
    auto status = napi_create_object(env, &(*result));
    if (status != napi_ok) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "create object fail");
    }

    cb->env = env;
    cb->data.device = inputDevice;
    *result = JsUtil::GetDeviceInfo(cb);
    if (*result == nullptr) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "GetDeviceInfo fail");
    }
}

napi_value JsInputDeviceManager::GetDeviceInfoSync(napi_env env, int32_t id, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    CreateCallbackInfo(env, handle, cb);
    napi_value result = nullptr;
    auto callback = [env, &result, cb] (std::shared_ptr<InputDevice> inputDevice) {
        return GetDeviceInfoSyncCallback(env, &result, cb, inputDevice);
        };
    int32_t napiCode = InputManager::GetInstance()->GetDevice(id, callback);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return result;
}

napi_value JsInputDeviceManager::SetKeyboardRepeatDelay(napi_env env, int32_t delay, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    int32_t napiCode = InputManager::GetInstance()->SetKeyboardRepeatDelay(delay);
    EmitJsSetKeyboardRepeatDelay(cb, napiCode);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return ret;
}

napi_value JsInputDeviceManager::SetKeyboardRepeatRate(napi_env env, int32_t rate, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    int32_t napiCode = InputManager::GetInstance()->SetKeyboardRepeatRate(rate);
    EmitJsSetKeyboardRepeatRate(cb, napiCode);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return ret;
}

napi_value JsInputDeviceManager::GetKeyboardRepeatDelay(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = [cb] (int32_t delay) { return EmitJsKeyboardRepeatDelay(cb, delay); };
    int32_t napiCode = InputManager::GetInstance()->GetKeyboardRepeatDelay(callback);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return ret;
}

napi_value JsInputDeviceManager::GetKeyboardRepeatRate(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = [cb] (int32_t rate) { return EmitJsKeyboardRepeatRate(cb, rate); };
    int32_t napiCode = InputManager::GetInstance()->GetKeyboardRepeatRate(callback);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return ret;
}

napi_value JsInputDeviceManager::GetIntervalSinceLastInput(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<JsUtil::CallbackInfo> cb = new (std::nothrow) JsUtil::CallbackInfo();
    CHKPP(cb);
    napi_value ret = CreateCallbackInfo(env, handle, cb);
    auto callback = [cb] (int64_t timeInterval) { return EmitJsGetIntervalSinceLastInput(cb, timeInterval); };
    int32_t napiCode = InputManager::GetInstance()->GetIntervalSinceLastInput(callback);
    if (napiCode != OTHER_ERROR && napiCode != RET_OK) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid input device id");
    }
    return ret;
}

void JsInputDeviceManager::ResetEnv()
{
    CALL_DEBUG_ENTER;
    JsEventTarget::ResetEnv();
}
} // namespace MMI
} // namespace OHOS