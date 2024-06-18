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

#include "js_short_key_manager.h"

#include "napi_constants.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsShortKeyManager"

namespace OHOS {
namespace MMI {
namespace {
enum class ReturnType {
    VOID,
    BOOL,
    NUMBER,
};
} // namespace

bool JsCommon::TypeOf(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valueType = napi_undefined;
    CHKRF(napi_typeof(env, value, &valueType), TYPEOF);
    return valueType == type;
}

AsyncContext::~AsyncContext()
{
    CALL_DEBUG_ENTER;
    if (work != nullptr) {
        CHKRV(napi_delete_async_work(env, work), DELETE_ASYNC_WORK);
    }
    if (callback != nullptr && env != nullptr) {
        CHKRV(napi_delete_reference(env, callback), DELETE_REFERENCE);
        env = nullptr;
    }
}

static bool GetResult(sptr<AsyncContext> asyncContext, napi_value * results, int32_t size)
{
    CALL_DEBUG_ENTER;
    const int32_t length = 2;
    if (size < length) {
        MMI_HILOGE("Results size less than 2");
        return false;
    }
    napi_env env = asyncContext->env;
    if (asyncContext->errorCode != RET_OK) {
        if (asyncContext->errorCode == RET_ERR) {
            MMI_HILOGE("Other errors");
            return false;
        }
        NapiError codeMsg;
        if (!UtilNapiError::GetApiError(asyncContext->errorCode, codeMsg)) {
            MMI_HILOGE("ErrorCode not found, errCode:%{public}d", asyncContext->errorCode);
            return false;
        }
        napi_value errCode = nullptr;
        napi_value errMsg = nullptr;
        napi_value businessError = nullptr;
        CHKRF(napi_create_int32(env, asyncContext->errorCode, &errCode), CREATE_INT32);
        CHKRF(napi_create_string_utf8(env, codeMsg.msg.c_str(),
            NAPI_AUTO_LENGTH, &errMsg), CREATE_STRING_UTF8);
        CHKRF(napi_create_error(env, nullptr, errMsg, &businessError), CREATE_ERROR);
        CHKRF(napi_set_named_property(env, businessError, ERR_CODE.c_str(), errCode), SET_NAMED_PROPERTY);
        results[0] = businessError;
    } else {
        CHKRF(napi_get_undefined(env, &results[0]), GET_UNDEFINED);
    }

    ReturnType resultType;
    asyncContext->reserve >> resultType;
    if (resultType == ReturnType::BOOL) {
        bool temp;
        asyncContext->reserve >> temp;
        CHKRF(napi_get_boolean(env, temp, &results[1]), GET_BOOLEAN);
    } else if (resultType == ReturnType::NUMBER) {
        int32_t temp;
        asyncContext->reserve >> temp;
        CHKRF(napi_create_int32(env, temp, &results[1]), CREATE_INT32);
    } else {
        CHKRF(napi_get_undefined(env, &results[1]), GET_UNDEFINED);
    }
    return true;
}

void AsyncCallbackWork(sptr<AsyncContext> asyncContext)
{
    CALL_DEBUG_ENTER;
    CHKPV(asyncContext);
    CHKPV(asyncContext->env);
    napi_env env = asyncContext->env;
    napi_value resource = nullptr;
    CHKRV(napi_create_string_utf8(env, "AsyncCallbackWork", NAPI_AUTO_LENGTH, &resource), CREATE_STRING_UTF8);
    asyncContext->IncStrongRef(nullptr);
    napi_status status = napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void* data) {
            MMI_HILOGD("async_work callback function is called");
        },
        [](napi_env env, napi_status status, void* data) {
            sptr<AsyncContext> asyncContext(static_cast<AsyncContext *>(data));
            /**
             * After the asynchronous task is created, the asyncCallbackInfo reference count is reduced
             * to 0 destruction, so you need to add 1 to the asyncCallbackInfo reference count when the
             * asynchronous task is created, and subtract 1 from the reference count after the naked
             * pointer is converted to a pointer when the asynchronous task is executed, the reference
             * count of the smart pointer is guaranteed to be 1.
             */
            asyncContext->DecStrongRef(nullptr);
            napi_value results[2] = { 0 };
            int32_t size = 2;
            if (!GetResult(asyncContext, results, size)) {
                MMI_HILOGE("Failed to create napi data");
                return;
            }
            if (asyncContext->deferred) {
                if (asyncContext->errorCode == RET_OK) {
                    CHKRV(napi_resolve_deferred(env, asyncContext->deferred, results[1]), RESOLVE_DEFERRED);
                } else {
                    CHKRV(napi_reject_deferred(env, asyncContext->deferred, results[0]), REJECT_DEFERRED);
                }
            } else {
                napi_value callback = nullptr;
                CHKRV(napi_get_reference_value(env, asyncContext->callback, &callback), GET_REFERENCE_VALUE);
                napi_value callResult = nullptr;
                CHKRV(napi_call_function(env, nullptr, callback, size, results, &callResult), CALL_FUNCTION);
            }
        },
        asyncContext.GetRefPtr(), &asyncContext->work);
    if (status != napi_ok ||
        napi_queue_async_work_with_qos(env, asyncContext->work, napi_qos_t::napi_qos_user_initiated) != napi_ok) {
        MMI_HILOGE("Create async work failed");
        asyncContext->DecStrongRef(nullptr);
    }
}

napi_value JsShortKeyManager::SetKeyDownDuration(napi_env env, const std::string &businessId, int32_t delay,
    napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetKeyDownDuration(businessId, delay);
    if (ret == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    } else if (ret == COMMON_PARAMETER_ERROR) {
        MMI_HILOGE("Invalid param");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "param is invalid");
        return nullptr;
    }
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    asyncContext->errorCode = ret;
    asyncContext->reserve << ReturnType::VOID;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        if (napi_get_undefined(env, &promise) != napi_ok) {
            CHKRP(napi_delete_reference(env, asyncContext->callback), DELETE_REFERENCE);
            return nullptr;
        }
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}
} // namespace MMI
} // namespace OHOS