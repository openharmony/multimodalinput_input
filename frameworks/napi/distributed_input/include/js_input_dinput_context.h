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

#ifndef JS_INPUT_DINPUT_CONTEXT_H
#define JS_INPUT_DINPUT_CONTEXT_H

#include "js_input_dinput_manager.h"

namespace OHOS {
namespace MMI {
class JsInputDinputContext final {
public:
    JsInputDinputContext() = default;
    ~JsInputDinputContext() = default;
    static JsInputDinputContext* GetInstance(napi_env env);
    static napi_value Export(napi_env env, napi_value exports);
    static napi_value PrepareRemoteInput(napi_env env, napi_callback_info info);
    static napi_value UnprepareRemoteInput(napi_env env, napi_callback_info info);
    static napi_value StartRemoteInput(napi_env env, napi_callback_info info);
    static napi_value StopRemoteInput(napi_env env, napi_callback_info info);
    static napi_value GetRemoteInputAbility(napi_env env, napi_callback_info info);

private:
    static napi_value CreateInstance(napi_env env);
    static napi_value JsConstructor(napi_env env, napi_callback_info info);
    static napi_value Init(napi_env env, napi_value exports);
    static napi_value InitInputAbilityTypeEnum(napi_env env, napi_value exports);
    static napi_value EnumTypeConstructor(napi_env env, napi_callback_info info);

    static napi_value GetParameter(napi_env env, napi_callback_info info, napi_ref &first);
    static napi_value GetParameter(napi_env env, napi_callback_info info,
        std::string &first, napi_ref &second);
    static napi_value GetParameter(napi_env env, napi_callback_info info,
        int32_t &first, int32_t &second, napi_ref &third);
    static napi_value GetParameter(napi_env env, napi_callback_info info,
        std::string &first, int32_t second, napi_ref &third);
    static napi_value GetParameter(napi_env env, napi_callback_info info,
        std::string &first, std::vector<uint32_t> &second, napi_ref &third);
    static bool TypeOf(napi_env env, napi_value value, napi_valuetype type);
    std::shared_ptr<JsInputDinputManager> GetJsInputDinputMgr() const;
    std::shared_ptr<JsInputDinputManager> mgr_ { std::make_shared<JsInputDinputManager>() };
    napi_ref contextRef_ { nullptr };
    std::mutex mtx_;
};
} // namespace MMI
} // namespace OHOS

#endif // JS_INPUT_DEVICE_CONTEXT_H