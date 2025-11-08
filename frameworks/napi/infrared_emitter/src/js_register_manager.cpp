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

#include "js_register_manager.h"

#include "define_multimodal.h"
#include "napi_constants.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsRegisterManager"

namespace OHOS {
namespace MMI {
JsRegisterManager& JsRegisterManager::GetInstance()
{
    static JsRegisterManager instance;
    return instance;
}

napi_value JsRegisterManager::JsHasIrEmitter(napi_env env)
{
    CALL_DEBUG_ENTER;
    sptr<JsRegister::CallbackInfo> cb = new (std::nothrow) JsRegister::CallbackInfo();
    if (cb == nullptr) {
        MMI_HILOGE("Check cb is nullptr");
        return nullptr;
    }
    cb->env = env;
    napi_value promise = nullptr;
    if (napi_create_promise(env, &cb->deferred, &promise) != napi_ok) {
        MMI_HILOGE("napi_create_promise failed");
        return nullptr;
    }
    EmitHasIrEmitter(cb);
    return promise;
}

void JsRegisterManager::EmitHasIrEmitter(sptr<JsRegister::CallbackInfo> cb)
{
    CALL_DEBUG_ENTER;
    if (cb == nullptr || cb->env == nullptr) {
        MMI_HILOGE("cb or env is nullptr");
        return;
    }
    bool hasIrEmitter = false;
    cb->data.hasIrEmitter = hasIrEmitter;
    cb->errCode = RET_OK;
    uv_loop_s *loop = nullptr;
    if (napi_get_uv_event_loop(cb->env, &loop) != napi_ok) {
        MMI_HILOGE("napi_get_uv_event_loop failed");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        MMI_HILOGE("Check work is nullptr");
        return;
    }
    cb->IncStrongRef(nullptr);
    work->data = cb.GetRefPtr();
    int32_t ret = -1;
    ret = uv_queue_work_with_qos(
        loop,
        work,
        [](uv_work_t *work) {
            MMI_HILOGD("uv_queue_work callback function is called");
            JsRegister::CallJsHasIrEmitterTask(work);
        },
        JsRegister::CallJsHasIrEmitterPromise,
        uv_qos_user_initiated);
    if (ret != 0) {
        MMI_HILOGE("uv_queue_work_with_qos failed");
        cb->DecStrongRef(nullptr);
        JsRegister::DeletePtr<uv_work_t *>(work);
    }
}
} // namespace MMI
} // namespace OHOS