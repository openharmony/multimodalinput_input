/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef JS_REGISTER_UTIL_H
#define JS_REGISTER_UTIL_H
#include "js_register_module.h"
#include "key_event.h"
#include <array>
namespace OHOS {
namespace MMI {
void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int32_t value);
void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, std::string value);

bool GetNamedPropertyBool(const napi_env &env, const napi_value &object, const std::string &name);
std::string GetNamedPropertyString(const napi_env &env, const napi_value &object, const std::string &name);
int32_t GetNamedPropertyInt32(const napi_env &env, const napi_value &object, const std::string &name);
std::vector<int32_t> GetCppArrayInt(napi_value value, napi_env env);
int32_t AddEventCallback(const napi_env &env, OHOS::MMI::CallbackMaps &callbackMaps,
    OHOS::MMI::KeyEventMonitorInfo *event, int32_t &preSubscribeId);
int32_t DelEventCallback(const napi_env &env, OHOS::MMI::CallbackMaps &callbackMaps,
    OHOS::MMI::KeyEventMonitorInfo *event, int32_t &subscribeId);
void EmitAsyncCallbackWork(OHOS::MMI::KeyEventMonitorInfo *event);
}
}

#endif // JS_REGISTER_UTIL_H