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

#ifndef JS_POINTER_CONTEXT_H
#define JS_POINTER_CONTEXT_H
#include "js_pointer_manager.h"

namespace OHOS {
namespace MMI {
class JsPointerContext {
public:
    JsPointerContext();
    DISALLOW_COPY_AND_MOVE(JsPointerContext);
    ~JsPointerContext() = default;
    static napi_value Export(napi_env env, napi_value exports);
    static napi_value SetPointerVisible(napi_env env, napi_callback_info info);
    static napi_value IsPointerVisible(napi_env env, napi_callback_info info);
    static napi_value SetPointerStyle(napi_env env, napi_callback_info info);
    static napi_value GetPointerStyle(napi_env env, napi_callback_info info);
    std::shared_ptr<JsPointerManager> GetJsPointerMgr() const;
    static napi_value SetPointerSpeed(napi_env env, napi_callback_info info);
    static napi_value GetPointerSpeed(napi_env env, napi_callback_info info);

private:
    static napi_value CreateInstance(napi_env env);
    static JsPointerContext* GetInstance(napi_env env);
    static napi_value CreateJsObject(napi_env env, napi_callback_info info);
    static napi_value EnumConstructor(napi_env env, napi_callback_info info);
    static napi_value CreatePointerStyle(napi_env env, napi_value exports);
    std::shared_ptr<JsPointerManager> mgr_ { nullptr };
    napi_ref contextRef_ { nullptr };
};
} // namespace MMI
} // namespace OHOS

#endif // JS_POINTER_CONTEXT_H