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

napi_value JsInputDeviceManager::GetDeviceIds(napi_env env, napi_value handle)
{
    napi_value ret = CreateCallbackInfo(env, handle);
    if (handle == nullptr) {
        CHKPP(ret);
        InputDevImp.GetInputDeviceIdsAsync(JsEventTarget::userData_ - 1, EmitJsIdsPromise);
        return ret;
    }
    InputDevImp.GetInputDeviceIdsAsync(JsEventTarget::userData_ - 1, EmitJsIdsAsync);
    return nullptr;
}

napi_value JsInputDeviceManager::GetDevice(int32_t id, napi_env env, napi_value handle)
{
    napi_value ret = CreateCallbackInfo(env, handle);
    if (handle == nullptr) {
        InputDevImp.GetInputDeviceAsync(JsEventTarget::userData_ - 1, id, EmitJsDevPromise);
        return ret;
    }
    InputDevImp.GetInputDeviceAsync(JsEventTarget::userData_ - 1, id, EmitJsDevAsync);
    return nullptr;
}

void JsInputDeviceManager::ResetEnv()
{
    JsEventTarget::ResetEnv();
}
} // namespace MMI
} // namespace OHOS