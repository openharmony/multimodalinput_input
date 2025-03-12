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

#ifndef JS_REGISTER_UTIL_H
#define JS_REGISTER_UTIL_H

#include <uv.h>

#include "js_register_module.h"

namespace OHOS {
namespace MMI {
struct CallbackInfo : RefBase {
    napi_env env { nullptr };
    napi_ref ref { nullptr };
    napi_deferred deferred { nullptr };
    int32_t errCode { -1 };
    std::vector<std::unique_ptr<KeyOption>> keyOptions;
};

template <typename T>
static void DeletePtr(T &ptr)
{
    if (ptr != nullptr) {
        delete ptr;
        ptr = nullptr;
    }
}

void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int32_t value);
void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, uint32_t value);
void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, int64_t value);
void SetNamedProperty(const napi_env &env, napi_value &object, const std::string &name, std::string value);
bool GetNamedPropertyBool(const napi_env &env, const napi_value &object, const std::string &name, bool &ret);
std::string GetNamedPropertyString(const napi_env &env, const napi_value &object, const std::string &name);
std::optional<int32_t> GetNamedPropertyInt32(const napi_env &env, const napi_value &object, const std::string &name);
napi_value GetPreKeys(const napi_env &env, const napi_value &value, std::set<int32_t> &params);
int32_t GetPreSubscribeId(Callbacks &callbacks, sptr<KeyEventMonitorInfo> event);
int32_t AddEventCallback(const napi_env &env, Callbacks &callbacks, sptr<KeyEventMonitorInfo> event);
int32_t DelEventCallback(const napi_env &env, Callbacks &callbacks, sptr<KeyEventMonitorInfo> event,
    int32_t &subscribeId);
void EmitAsyncCallbackWork(sptr<KeyEventMonitorInfo> event);

napi_value ConvertHotkeyToNapiValue(napi_env env, const KeyOption &keyOption);
napi_value ConvertHotkeysToNapiArray(sptr<CallbackInfo> cb);
napi_value GreateBusinessError(napi_env env, int32_t errCode, std::string errMessage);
void CallHotkeyPromiseWork(uv_work_t *work, int32_t status);
void EmitSystemHotkey(sptr<CallbackInfo> cb);
napi_value GetSystemHotkey(napi_env env, napi_value handle = nullptr);
} // namespace MMI
} // namespace OHOS
#endif // JS_REGISTER_UTIL_H