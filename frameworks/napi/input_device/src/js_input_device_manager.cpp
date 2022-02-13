/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
void JsInputDeviceManager::GetDeviceIdsAsync(napi_env env, napi_value handle)
{
    SetContext(env, handle);
    auto &instance = InputDeviceImpl::GetInstance();
    instance.GetInputDeviceIdsAsync(EmitJsIdsAsync);
}

void JsInputDeviceManager::GetDeviceAsync(int32_t id, napi_env env, napi_value handle)
{
    SetContext(env, handle);
    auto &instance = InputDeviceImpl::GetInstance();
    instance.GetInputDeviceAsync(id, EmitJsDevAsync);
}

void JsInputDeviceManager::ResetEnv()
{
    JsEventTarget::ResetEnv();
}
} // namespace MMI
} // namespace OHOS