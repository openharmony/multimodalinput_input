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

#ifndef JS_REGISTER_H
#define JS_REGISTER_H

#include <uv.h>

#include "pointer_event.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "refbase.h"

namespace OHOS {
namespace MMI {
class JsRegister final {
public:

    struct CallbackData {
        bool hasIrEmitter { false };
    };

    struct CallbackInfo : RefBase {
        napi_env env { nullptr };
        napi_ref ref { nullptr };
        napi_deferred deferred { nullptr };
        int32_t errCode { -1 };
        CallbackData data;
    };

    static void CallJsHasIrEmitterTask(uv_work_t *work);
    static void CallJsHasIrEmitterPromise(uv_work_t *work, int32_t status);
    static napi_value GreateBusinessError(napi_env env, int32_t errCode, std::string errMessage);
    static void JsHasIrEmitterResolveDeferred(
        sptr<CallbackInfo> cb, napi_handle_scope scope, napi_value callResult);
    template <typename T>
    static void DeletePtr(T &ptr)
    {
        if (ptr != nullptr) {
            delete ptr;
            ptr = nullptr;
        }
    }
};
} // namespace MMI
} // namespace OHOS
#endif // JS_REGISTER_H