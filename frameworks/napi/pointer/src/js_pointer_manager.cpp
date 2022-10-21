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

#include "js_pointer_manager.h"

#include "napi_constants.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsPointerManager" };

enum class ReturnType {
    VOID,
    BOOL,
    NUMBER,
};
}

bool JsCommon::TypeOf(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valueType = napi_undefined;
    CHKRF(env, napi_typeof(env, value, &valueType), TYPEOF);
    if (valueType != type) {
        return false;
    }
    return true;
}

AsyncContext::~AsyncContext()
{
    CALL_DEBUG_ENTER;
    if (work != nullptr) {
        CHKRV(env, napi_delete_async_work(env, work), DELETE_ASYNC_WORK);
    }
    if (callback != nullptr && env != nullptr) {
        CHKRV(env, napi_delete_reference(env, callback), DELETE_REFERENCE);
        env = nullptr;
    }
}

bool getResult(sptr<AsyncContext> asyncContext, napi_value * results)
{
    CALL_DEBUG_ENTER;
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
        CHKRF(env, napi_create_int32(env, asyncContext->errorCode, &errCode), CREATE_INT32);
        CHKRF(env, napi_create_string_utf8(env, codeMsg.msg.c_str(),
            NAPI_AUTO_LENGTH, &errMsg), CREATE_STRING_UTF8);
        CHKRF(env, napi_create_error(env, nullptr, errMsg, &businessError), CREATE_ERROR);
        CHKRF(env, napi_set_named_property(env, businessError, ERR_CODE.c_str(), errCode), SET_NAMED_PROPERTY);
        results[0] = businessError;
    } else {
        CHKRF(env, napi_get_undefined(env, &results[0]), GET_UNDEFINED);
    }

    ReturnType resultType;
    asyncContext->reserve >> resultType;
    if (resultType == ReturnType::BOOL) {
        bool temp;
        asyncContext->reserve >> temp;
        CHKRF(env, napi_get_boolean(env, temp, &results[1]), CREATE_BOOL);
    } else if (resultType == ReturnType::NUMBER) {
        int32_t temp;
        asyncContext->reserve >> temp;
        CHKRF(env, napi_create_int32(env, temp, &results[1]), CREATE_INT32);
    } else {
        CHKRF(env, napi_get_undefined(env, &results[1]), GET_UNDEFINED);
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
    CHKRV(env, napi_create_string_utf8(env, "AsyncCallbackWork", NAPI_AUTO_LENGTH, &resource), CREATE_STRING_UTF8);
    asyncContext->IncStrongRef(nullptr);
    napi_status status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {},
        [](napi_env env, napi_status status, void* data) {
            sptr<AsyncContext> asyncContext(static_cast<AsyncContext *>(data));
            /**
             * After the asynchronous task is created, the asyncCallbackInfo reference count is reduced
             * to 0 destructions, so you need to add 1 to the asyncCallbackInfo reference count when the
             * asynchronous task is created, and subtract 1 from the reference count after the naked
             * pointer is converted to a pointer when the asynchronous task is executed, the reference
             * count of the smart pointer is guaranteed to be 1.
             */
            asyncContext->DecStrongRef(nullptr);
            napi_value results[2] = { 0 };
            if (!getResult(asyncContext, results)) {
                MMI_HILOGE("Failed to create napi data");
                return;
            }
            if (asyncContext->deferred) {
                if (asyncContext->errorCode == RET_OK) {
                    CHKRV(env, napi_resolve_deferred(env, asyncContext->deferred, results[1]), RESOLVE_DEFERRED);
                } else {
                    CHKRV(env, napi_reject_deferred(env, asyncContext->deferred, results[0]), REJECT_DEFERRED);
                }
            } else {
                napi_value callback = nullptr;
                CHKRV(env, napi_get_reference_value(env, asyncContext->callback, &callback), GET_REFERENCE);
                napi_value callResult = nullptr;
                CHKRV(env, napi_call_function(env, nullptr, callback, 2, results, &callResult), CALL_FUNCTION);
            }
        },
        asyncContext.GetRefPtr(), &asyncContext->work);
    if (status != napi_ok || napi_queue_async_work(env, asyncContext->work) != napi_ok) {
        MMI_HILOGE("Create async work failed");
        asyncContext->DecStrongRef(nullptr);
    }
}

napi_value JsPointerManager::SetPointerVisible(napi_env env, bool visible, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);

    asyncContext->errorCode = InputManager::GetInstance()->SetPointerVisible(visible);
    asyncContext->reserve << ReturnType::VOID;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(env, napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(env, napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(env, napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::IsPointerVisible(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);

    bool visible = InputManager::GetInstance()->IsPointerVisible();
    asyncContext->errorCode = ERR_OK;
    asyncContext->reserve << ReturnType::BOOL << visible;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(env, napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(env, napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(env, napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::SetPointerSpeed(napi_env env, int32_t pointerSpeed, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    asyncContext->errorCode = InputManager::GetInstance()->SetPointerSpeed(pointerSpeed);
    asyncContext->reserve << ReturnType::VOID;
    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(env, napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(env, napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(env, napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::GetPointerSpeed(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    int32_t pointerSpeed = 0;
    asyncContext->errorCode = InputManager::GetInstance()->GetPointerSpeed(pointerSpeed);
    asyncContext->reserve << ReturnType::NUMBER << pointerSpeed;
    napi_value promise = nullptr;
    uint32_t initial_refcount = 1;
    if (handle != nullptr) {
        CHKRP(env, napi_create_reference(env, handle, initial_refcount, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(env, napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(env, napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::SetPointerStyle(napi_env env, int32_t windowid, int32_t pointerStyle, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    asyncContext->errorCode = InputManager::GetInstance()->SetPointerStyle(windowid, pointerStyle);
    asyncContext->reserve << ReturnType::VOID;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(env, napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(env, napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(env, napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::GetPointerStyle(napi_env env, int32_t windowid, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    int32_t pointerStyle = 0;
    asyncContext->errorCode = InputManager::GetInstance()->GetPointerStyle(windowid, pointerStyle);
    asyncContext->reserve << ReturnType::NUMBER << pointerStyle;
    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(env, napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(env, napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(env, napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}
} // namespace MMI
} // namespace OHOS