/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "js_input_device_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputDeviceManager" };
} // namespace

JsInputDeviceManager::JsInputDeviceManager()
{
    CALL_LOG_ENTER;
    InputDevImp.RegisterInputDeviceMonitor(TargetOn);
}

JsInputDeviceManager::~JsInputDeviceManager() {}

void JsInputDeviceManager::RegisterInputDeviceMonitor(napi_env env, std::string type, napi_value handle)
{
    CALL_LOG_ENTER;
    AddMonitor(env, type, handle);
}

void JsInputDeviceManager::UnRegisterInputDeviceMonitor(napi_env env, std::string type, napi_value handle)
{
    CALL_LOG_ENTER;
    RemoveMonitor(env, type, handle);
}

napi_value JsInputDeviceManager::GetDeviceIds(napi_env env, napi_value handle)
{
    CALL_LOG_ENTER;
    napi_value ret = CreateCallbackInfo(env, handle);
    InputDevImp.GetInputDeviceIdsAsync(JsEventTarget::userData_ - 1, EmitJsIds);
    return ret;
}

napi_value JsInputDeviceManager::GetDevice(napi_env env, int32_t id, napi_value handle)
{
    CALL_LOG_ENTER;
    napi_value ret = CreateCallbackInfo(env, handle);
    InputDevImp.GetInputDeviceAsync(JsEventTarget::userData_ - 1, id, EmitJsDev);
    return ret;
}

napi_value JsInputDeviceManager::GetKeystrokeAbility(napi_env env, int32_t id, std::vector<int32_t> keyCodes,
                                                     napi_value handle)
{
    CALL_LOG_ENTER;
    napi_value ret = CreateCallbackInfo(env, handle);
    InputDevImp.GetKeystrokeAbility(JsEventTarget::userData_ - 1, id, keyCodes, EmitJsKeystrokeAbility);
    return ret;
}

void JsInputDeviceManager::ResetEnv()
{
    CALL_LOG_ENTER;
    InputDevImp.UnRegisterInputDeviceMonitor();
    JsEventTarget::ResetEnv();
}
} // namespace MMI
} // namespace OHOS