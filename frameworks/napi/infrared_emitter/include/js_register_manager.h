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

#ifndef JS_REGISTER_MANAGER_H
#define JS_REGISTER_MANAGER_H

#include "js_register.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class JsRegisterManager final {
public:
    static JsRegisterManager& GetInstance();
    DISALLOW_COPY_AND_MOVE(JsRegisterManager);
    ~JsRegisterManager() = default;

    napi_value JsHasIrEmitter(napi_env env);
    void EmitHasIrEmitter(sptr<JsRegister::CallbackInfo> cb);

private:
    JsRegisterManager() = default;

private:
    std::mutex mutex_;
    std::mutex envMutex_;
};

#define JS_REGISTER_MGR JsRegisterManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // JS_REGISTER_MANAGER_H