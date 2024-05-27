/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef JS_SHORT_KEY_CONTEXT_H
#define JS_SHORT_KEY_CONTEXT_H
#include "js_short_key_manager.h"

namespace OHOS {
namespace MMI {
class JsShortKeyContext {
public:
    JsShortKeyContext();
    DISALLOW_COPY_AND_MOVE(JsShortKeyContext);
    ~JsShortKeyContext() = default;
    static napi_value Export(napi_env env, napi_value exports);
    std::shared_ptr<JsShortKeyManager> GetJsShortKeyMgr() const;
    static napi_value SetKeyDownDuration(napi_env env, napi_callback_info info);

private:
    static napi_value GetNapiInt32(napi_env env, int32_t code);
    static napi_value EnumClassConstructor(napi_env env, napi_callback_info info);
    static napi_value CreateInstance(napi_env env);
    static JsShortKeyContext* GetInstance(napi_env env);
    static napi_value CreateJsObject(napi_env env, napi_callback_info info);
    std::shared_ptr<JsShortKeyManager> mgr_ { nullptr };
    napi_ref contextRef_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // JS_SHORT_KEY_CONTEXT_H