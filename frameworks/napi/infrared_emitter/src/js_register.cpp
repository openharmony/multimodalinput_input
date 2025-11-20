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

#include "js_register.h"

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager.h"
#include "js_register_manager.h"
#include "napi_constants.h"
#include "util_napi_error.h"
#include "util_napi_value.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsRegister"

namespace OHOS {
namespace MMI {
namespace {
} // namespace
void JsRegister::CallJsHasIrEmitterTask(uv_work_t *work)
{
    if (work == nullptr) {
        MMI_HILOGE("Check work is nullptr");
        return;
    }
    CallbackInfo* cb = static_cast<CallbackInfo*>(work->data);
    if (cb == nullptr) {
        MMI_HILOGE("Check cb is nullptr");
        return;
    }
    int32_t napiCode = InputManager::GetInstance()->HasIrEmitter(cb->data.hasIrEmitter);
    if (napiCode == ERROR_NO_PERMISSION) {
        napiCode = COMMON_PERMISSION_CHECK_ERROR;
    }
    cb->errCode = napiCode;
}

void JsRegister::CallJsHasIrEmitterPromise(uv_work_t *work, int32_t status)
{
    CALL_DEBUG_ENTER;
    if (work == nullptr) {
        MMI_HILOGE("Check work is nullptr");
        return;
    }
    sptr<CallbackInfo> cb(static_cast<CallbackInfo *>(work->data));
    DeletePtr<uv_work_t *>(work);
    if (cb == nullptr) {
        MMI_HILOGE("Check cb is nullptr");
        return;
    }
    cb->DecStrongRef(nullptr);
    if (cb->env == nullptr) {
        MMI_HILOGE("Check env is nullptr");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(cb->env, &scope);
    if (scope == nullptr) {
        MMI_HILOGE("Check scope is nullptr");
        return;
    }
    CallJsHasIrEmitterPromiseEx(cb, scope);
}

void JsRegister::CallJsHasIrEmitterPromiseEx(sptr<CallbackInfo> cb, napi_handle_scope scope)
{
    napi_value callResult = nullptr;
    if (cb->errCode != RET_OK) {
        if (cb->errCode == RET_ERR) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Other errors");
            return;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(cb->errCode, codeMsg)) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("Error code %{public}d not found", cb->errCode);
            return;
        }
        callResult = CreateBusinessError(cb->env, cb->errCode, codeMsg.msg);
        if (callResult == nullptr) {
            napi_close_handle_scope(cb->env, scope);
            MMI_HILOGE("The callResult is nullptr");
            return;
        }
        if (napi_reject_deferred(cb->env, cb->deferred, callResult) != napi_ok) {
            MMI_HILOGE("napi_reject_deferred failed");
            napi_close_handle_scope(cb->env, scope);
            return;
        }
    } else {
        JsHasIrEmitterResolveDeferred(cb, scope, callResult);
    }
    napi_close_handle_scope(cb->env, scope);
}

void JsRegister::JsHasIrEmitterResolveDeferred(
    sptr<CallbackInfo> cb, napi_handle_scope scope, napi_value callResult)
{
    if (cb == nullptr) {
        MMI_HILOGE("Check cb is nullptr");
        return;
    }
    if (napi_get_boolean(cb->env, cb->data.hasIrEmitter, &callResult) != napi_ok) {
        MMI_HILOGE("napi_get_boolean failed");
        return;
    }
    if (napi_resolve_deferred(cb->env, cb->deferred, callResult) != napi_ok) {
        MMI_HILOGE("napi_resolve_deferred failed");
        return;
    }
}

napi_value JsRegister::CreateBusinessError(napi_env env, int32_t errCode, std::string errMessage)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    napi_value resultCode = nullptr;
    napi_value resultMessage = nullptr;
    if (napi_create_int32(env, errCode, &resultCode) != napi_ok) {
        MMI_HILOGE("napi_create_int32 failed");
        return nullptr;
    }
    if (napi_create_string_utf8(env, errMessage.data(), NAPI_AUTO_LENGTH, &resultMessage) != napi_ok) {
        MMI_HILOGE("napi_create_string_utf8 failed");
        return nullptr;
    }
    if (napi_create_error(env, nullptr, resultMessage, &result) != napi_ok) {
        MMI_HILOGE("napi_create_error failed");
        return nullptr;
    }
    if (napi_set_named_property(env, result, ERR_CODE.c_str(), resultCode) != napi_ok) {
        MMI_HILOGE("napi_set_named_property failed");
        return nullptr;
    }
    return result;
}
} // namespace MMI
} // namespace OHOS