/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef JS_INPUT_DINPUT_MANAGER_H
#define JS_INPUT_DINPUT_MANAGER_H

#include <memory>
#include <set>
#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "utils/log.h"

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "util_napi.h"

#define PARAMERTER_NUM 1
namespace OHOS {
namespace MMI {
template <class T>
class CallbackInfo {
public:
    napi_env env { nullptr };
    napi_ref ref { nullptr };
    napi_async_work asyncWork { nullptr };
    napi_deferred deferred { nullptr };
    napi_value promise { nullptr };
    int32_t mouseX = 0;
    int32_t mouseY = 0;
    T returnResult;
};
enum InputAbilityType {
    MOUSE = 1,
    KEYBOARD = 2,
    TOUCHPAD = 4,
};

class JsInputDinputManager {
public:
    napi_value PrepareRemoteInput(napi_env env, const std::string& deviceId, napi_ref handle);
    napi_value UnprepareRemoteInput(napi_env env, const std::string& deviceId, napi_ref handle);
    napi_value StartRemoteInput(napi_env env, const std::string& deviceId,
        const std::vector<uint32_t>& inputAbility, napi_ref handle);
    napi_value StopRemoteInput(napi_env env, const std::string& deviceId,
        const std::vector<uint32_t>& inputAbility, napi_ref handle);
    napi_value GetRemoteInputAbility(napi_env env, const std::string& deviceId, napi_ref handle);
public:
    template <typename T>
    CallbackInfo<T>* CreateCallbackInfo(napi_env env, napi_ref handle)
    {
        auto cb = new (std::nothrow) CallbackInfo<T>;
        if (cb == nullptr) {
            return nullptr;
        }
        cb->env = env;
        if (handle == nullptr) {
            if (napi_create_promise(env, &cb->deferred, &cb->promise) != napi_ok) {
                delete cb;
                cb = nullptr;
                napi_throw_error(env, nullptr, "Failed to create promise");
            }
        } else {
            cb->ref = handle;
        }
        return cb;
    }

private:
    static void HandleCallBack(CallbackInfo<int32_t>* cb);
    static void HandleCallBack(CallbackInfo<std::set<int32_t>>* cb);
    static napi_value MakeInputAbilityObj(napi_env env, std::set<int32_t> types);
    static uint32_t GetAbilityType(std::vector<uint32_t> abilities);

    static void CallFunctionPromise(napi_env env, napi_deferred deferred, napi_value object);
    static void CallFunctionAsync(napi_env env, napi_ref handleRef, size_t count, napi_value* object);
    std::mutex cbMutex_;
};
} // namespace MMI
} // namespace OHOS
#endif // JS_INPUT_DINPUT_MANAGER_H