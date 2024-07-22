/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_pointer_manager.h"

#include "napi_constants.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsPointerManager"

namespace OHOS {
namespace MMI {
namespace {
enum class ReturnType {
    VOID,
    BOOL,
    NUMBER,
};
constexpr int32_t TOUCHPAD_SCROLL_ROWS { 3 };
}

bool JsCommon::TypeOf(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valueType = napi_undefined;
    CHKRF(napi_typeof(env, value, &valueType), TYPEOF);
    if (valueType != type) {
        return false;
    }
    return true;
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

static bool GetResult(sptr<AsyncContext> asyncContext, napi_value *results, int32_t size)
{
    CALL_DEBUG_ENTER;
    int32_t length = 2;
    if (size < length) {
        MMI_HILOGE("results size less than 2");
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
        int32_t temp = 0;
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

napi_value JsPointerManager::SetPointerVisible(napi_env env, bool visible, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);

    asyncContext->errorCode = InputManager::GetInstance()->SetPointerVisible(visible);
    asyncContext->reserve << ReturnType::VOID;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::SetPointerVisibleSync(napi_env env, bool visible)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetPointerVisible(visible);
    napi_value result = nullptr;
    if (napi_get_undefined(env, &result) != napi_ok) {
        MMI_HILOGE("Get undefined result is failed");
        return nullptr;
    }
    return result;
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
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::IsPointerVisibleSync(napi_env env)
{
    CALL_DEBUG_ENTER;
    bool visible = InputManager::GetInstance()->IsPointerVisible();
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, visible, &result));
    return result;
}

napi_value JsPointerManager::SetPointerColor(napi_env env, int32_t color, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    asyncContext->errorCode = InputManager::GetInstance()->SetPointerColor(color);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
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

napi_value JsPointerManager::GetPointerColor(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    int32_t color = 1;
    asyncContext->errorCode = InputManager::GetInstance()->GetPointerColor(color);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    asyncContext->reserve << ReturnType::NUMBER << color;
    napi_value promise = nullptr;
    uint32_t initialRefCount = 1;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, initialRefCount, &asyncContext->callback), CREATE_REFERENCE);
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

napi_value JsPointerManager::SetPointerColorSync(napi_env env, int32_t color)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetPointerColor(color);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }

    napi_value result = nullptr;
    if (napi_get_undefined(env, &result) != napi_ok) {
        MMI_HILOGE("Get undefined result is failed");
        return nullptr;
    }
    return result;
}

napi_value JsPointerManager::GetPointerColorSync(napi_env env)
{
    CALL_DEBUG_ENTER;
    int32_t color = 1;
    auto errorCode = InputManager::GetInstance()->GetPointerColor(color);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, color, &result));
    return result;
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
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::SetPointerSpeedSync(napi_env env, int32_t pointerSpeed)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetPointerSpeed(pointerSpeed);
    napi_value result = nullptr;
    if (napi_get_undefined(env, &result) != napi_ok) {
        MMI_HILOGE("Get undefined result is failed");
        return nullptr;
    }
    return result;
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
        CHKRP(napi_create_reference(env, handle, initial_refcount, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::GetPointerSpeedSync(napi_env env)
{
    CALL_DEBUG_ENTER;
    int32_t pointerSpeed = 0;
    InputManager::GetInstance()->GetPointerSpeed(pointerSpeed);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, pointerSpeed, &result));
    return result;
}

napi_value JsPointerManager::SetMouseScrollRows(napi_env env, int32_t rows, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    asyncContext->errorCode = InputManager::GetInstance()->SetMouseScrollRows(rows);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
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

napi_value JsPointerManager::GetMouseScrollRows(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    int32_t rows = 3;
    asyncContext->errorCode = InputManager::GetInstance()->GetMouseScrollRows(rows);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    asyncContext->reserve << ReturnType::NUMBER << rows;
    napi_value promise = nullptr;
    uint32_t initialRefCount = 1;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, initialRefCount, &asyncContext->callback), CREATE_REFERENCE);
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

napi_value JsPointerManager::SetPointerLocation(napi_env env, int32_t x, int32_t y, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    asyncContext->errorCode = InputManager::GetInstance()->SetPointerLocation(x, y);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
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

napi_value JsPointerManager::SetCustomCursor(napi_env env, int32_t windowId, void* pixelMap, CursorFocus focus)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    asyncContext->errorCode = InputManager::GetInstance()->SetCustomCursor(windowId, pixelMap, focus.x, focus.y);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    asyncContext->reserve << ReturnType::VOID;
    napi_value promise = nullptr;
    CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::SetCustomCursorSync(napi_env env, int32_t windowId, void* pixelMap, CursorFocus focus)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->SetCustomCursor(windowId, pixelMap, focus.x, focus.y);
    napi_value result = nullptr;
    if (napi_get_undefined(env, &result) != napi_ok) {
        MMI_HILOGE("Get undefined result is failed");
        return nullptr;
    }
    return result;
}

napi_value JsPointerManager::SetPointerSize(napi_env env, int32_t size, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    asyncContext->errorCode = InputManager::GetInstance()->SetPointerSize(size);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
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

napi_value JsPointerManager::GetPointerSize(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    int32_t size = 1;
    asyncContext->errorCode = InputManager::GetInstance()->GetPointerSize(size);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    asyncContext->reserve << ReturnType::NUMBER << size;
    napi_value promise = nullptr;
    uint32_t initialRefCount = 1;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, initialRefCount, &asyncContext->callback), CREATE_REFERENCE);
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

napi_value JsPointerManager::SetPointerSizeSync(napi_env env, int32_t size)
{
    CALL_DEBUG_ENTER;
    auto errorCode = InputManager::GetInstance()->SetPointerSize(size);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }

    napi_value result = nullptr;
    if (napi_get_undefined(env, &result) != napi_ok) {
        MMI_HILOGE("Get undefined result is failed");
        return nullptr;
    }
    return result;
}

napi_value JsPointerManager::GetPointerSizeSync(napi_env env)
{
    CALL_DEBUG_ENTER;
    int32_t size = 1;
    auto errorCode = InputManager::GetInstance()->GetPointerSize(size);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, size, &result));
    return result;
}

napi_value JsPointerManager::SetPointerStyle(napi_env env, int32_t windowid, int32_t pointerStyle, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    PointerStyle style;
    style.id = pointerStyle;
    asyncContext->errorCode = InputManager::GetInstance()->SetPointerStyle(windowid, style);
    asyncContext->reserve << ReturnType::VOID;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::SetPointerStyleSync(napi_env env, int32_t windowid, int32_t pointerStyle)
{
    CALL_DEBUG_ENTER;
    PointerStyle style;
    style.id = pointerStyle;
    InputManager::GetInstance()->SetPointerStyle(windowid, style);
    napi_value result = nullptr;
    if (napi_get_undefined(env, &result) != napi_ok) {
        MMI_HILOGE("Get undefined result is failed");
        return nullptr;
    }
    return result;
}

napi_value JsPointerManager::GetPointerStyle(napi_env env, int32_t windowid, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    PointerStyle pointerStyle;
    asyncContext->errorCode = InputManager::GetInstance()->GetPointerStyle(windowid, pointerStyle);
    asyncContext->reserve << ReturnType::NUMBER << pointerStyle.id;
    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::GetPointerStyleSync(napi_env env, int32_t windowid)
{
    CALL_DEBUG_ENTER;
    PointerStyle pointerStyle;
    InputManager::GetInstance()->GetPointerStyle(windowid, pointerStyle);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, pointerStyle.id, &result));
    return result;
}

napi_value JsPointerManager::EnterCaptureMode(napi_env env, int32_t windowId, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    if (asyncContext == nullptr) {
        THROWERR(env, "Create AsyncContext failed");
        return nullptr;
    }
    asyncContext->errorCode = InputManager::GetInstance()->EnterCaptureMode(windowId);
    asyncContext->reserve << ReturnType::VOID;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::LeaveCaptureMode(napi_env env, int32_t windowId, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    if (asyncContext == nullptr) {
        THROWERR(env, "Create AsyncContext failed");
        return nullptr;
    }

    asyncContext->errorCode = InputManager::GetInstance()->LeaveCaptureMode(windowId);
    asyncContext->reserve << ReturnType::VOID;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::SetMousePrimaryButton(napi_env env, int32_t primaryButton, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);

    asyncContext->errorCode = InputManager::GetInstance()->SetMousePrimaryButton(primaryButton);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    asyncContext->reserve << ReturnType::VOID;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::GetMousePrimaryButton(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    int32_t primaryButton = 0;
    asyncContext->errorCode = InputManager::GetInstance()->GetMousePrimaryButton(primaryButton);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    asyncContext->reserve << ReturnType::NUMBER << primaryButton;
    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::SetHoverScrollState(napi_env env, bool state, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);

    asyncContext->errorCode = InputManager::GetInstance()->SetHoverScrollState(state);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    asyncContext->reserve << ReturnType::VOID;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::GetHoverScrollState(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);

    bool state;
    asyncContext->errorCode = InputManager::GetInstance()->GetHoverScrollState(state);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    asyncContext->reserve << ReturnType::BOOL << state;

    napi_value promise = nullptr;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, 1, &asyncContext->callback), CREATE_REFERENCE);
        CHKRP(napi_get_undefined(env, &promise), GET_UNDEFINED);
    } else {
        CHKRP(napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    }
    AsyncCallbackWork(asyncContext);
    return promise;
}

napi_value JsPointerManager::SetTouchpadData(napi_env env, napi_value handle, int32_t errorCode)
{
    CALL_DEBUG_ENTER;
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }

    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);

    asyncContext->errorCode = errorCode;
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

napi_value JsPointerManager::GetTouchpadBoolData(napi_env env, napi_value handle, bool data, int32_t errorCode)
{
    CALL_DEBUG_ENTER;
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }

    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);

    asyncContext->errorCode = errorCode;
    asyncContext->reserve << ReturnType::BOOL << data;

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

napi_value JsPointerManager::GetTouchpadInt32Data(napi_env env, napi_value handle, int32_t data, int32_t errorCode)
{
    CALL_DEBUG_ENTER;
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }

    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);

    asyncContext->errorCode = errorCode;
    asyncContext->reserve << ReturnType::NUMBER << data;

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

napi_value JsPointerManager::SetTouchpadScrollSwitch(napi_env env, bool switchFlag, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetTouchpadScrollSwitch(switchFlag);
    return SetTouchpadData(env, handle, ret);
}

napi_value JsPointerManager::GetTouchpadScrollSwitch(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    int32_t ret = InputManager::GetInstance()->GetTouchpadScrollSwitch(switchFlag);
    return GetTouchpadBoolData(env, handle, switchFlag, ret);
}

napi_value JsPointerManager::SetTouchpadScrollDirection(napi_env env, bool state, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetTouchpadScrollDirection(state);
    return SetTouchpadData(env, handle, ret);
}

napi_value JsPointerManager::GetTouchpadScrollDirection(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    bool state = true;
    int32_t ret = InputManager::GetInstance()->GetTouchpadScrollDirection(state);
    return GetTouchpadBoolData(env, handle, state, ret);
}

napi_value JsPointerManager::SetTouchpadTapSwitch(napi_env env, bool switchFlag, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetTouchpadTapSwitch(switchFlag);
    return SetTouchpadData(env, handle, ret);
}

napi_value JsPointerManager::GetTouchpadTapSwitch(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    int32_t ret = InputManager::GetInstance()->GetTouchpadTapSwitch(switchFlag);
    return GetTouchpadBoolData(env, handle, switchFlag, ret);
}
napi_value JsPointerManager::SetTouchpadPointerSpeed(napi_env env, int32_t speed, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetTouchpadPointerSpeed(speed);
    return SetTouchpadData(env, handle, ret);
}

napi_value JsPointerManager::GetTouchpadPointerSpeed(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t speed = 0;
    int32_t ret = InputManager::GetInstance()->GetTouchpadPointerSpeed(speed);
    return GetTouchpadInt32Data(env, handle, speed, ret);
}

napi_value JsPointerManager::SetTouchpadPinchSwitch(napi_env env, bool switchFlag, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetTouchpadPinchSwitch(switchFlag);
    return SetTouchpadData(env, handle, ret);
}

napi_value JsPointerManager::GetTouchpadPinchSwitch(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    int32_t ret = InputManager::GetInstance()->GetTouchpadPinchSwitch(switchFlag);
    return GetTouchpadBoolData(env, handle, switchFlag, ret);
}

napi_value JsPointerManager::SetTouchpadSwipeSwitch(napi_env env, bool switchFlag, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetTouchpadSwipeSwitch(switchFlag);
    return SetTouchpadData(env, handle, ret);
}

napi_value JsPointerManager::GetTouchpadSwipeSwitch(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    int32_t ret = InputManager::GetInstance()->GetTouchpadSwipeSwitch(switchFlag);
    return GetTouchpadBoolData(env, handle, switchFlag, ret);
}

napi_value JsPointerManager::SetTouchpadRightClickType(napi_env env, int32_t type, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetTouchpadRightClickType(type);
    return SetTouchpadData(env, handle, ret);
}

napi_value JsPointerManager::GetTouchpadRightClickType(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t type = 1;
    int32_t ret = InputManager::GetInstance()->GetTouchpadRightClickType(type);
    return GetTouchpadInt32Data(env, handle, type, ret);
}

napi_value JsPointerManager::SetTouchpadRotateSwitch(napi_env env, bool rotateSwitch, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetTouchpadRotateSwitch(rotateSwitch);
    return SetTouchpadData(env, handle, ret);
}

napi_value JsPointerManager::GetTouchpadRotateSwitch(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    bool rotateSwitch = true;
    int32_t ret = InputManager::GetInstance()->GetTouchpadRotateSwitch(rotateSwitch);
    return GetTouchpadBoolData(env, handle, rotateSwitch, ret);
}

napi_value JsPointerManager::SetMoveEventFilters(napi_env env, bool flag)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetMoveEventFilters(flag);
    napi_value result = nullptr;
    CHKRP(napi_create_int32(env, ret, &result), CREATE_INT32);
    return result;
}

napi_value JsPointerManager::SetTouchpadThreeFingersTapSwitch(napi_env env, bool switchFlag, napi_value handle)
{
    CALL_DEBUG_ENTER;
    int32_t ret = InputManager::GetInstance()->SetTouchpadThreeFingersTapSwitch(switchFlag);
    return SetTouchpadData(env, handle, ret);
}

napi_value JsPointerManager::GetTouchpadThreeFingersTapSwitch(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    bool switchFlag = true;
    int32_t ret = InputManager::GetInstance()->GetTouchpadThreeFingersTapSwitch(switchFlag);
    return GetTouchpadBoolData(env, handle, switchFlag, ret);
}

napi_value JsPointerManager::EnableHardwareCursorStats(napi_env env, bool enable)
{
    CALL_DEBUG_ENTER;
    InputManager::GetInstance()->EnableHardwareCursorStats(enable);
    napi_value result = nullptr;
    if (napi_get_undefined(env, &result) != napi_ok) {
        MMI_HILOGE("Get undefined result is failed");
        return nullptr;
    }
    return result;
}

napi_value JsPointerManager::GetHardwareCursorStats(napi_env env)
{
    CALL_DEBUG_ENTER;
    uint32_t frameCount = 0;
    uint32_t vsyncCount = 0;
    InputManager::GetInstance()->GetHardwareCursorStats(frameCount, vsyncCount);
    napi_value result = nullptr;
    napi_status status = napi_create_object(env, &result);
    if (status != napi_ok) {
        MMI_HILOGE("Napi create object is failed");
        return nullptr;
    }
    MMI_HILOGD("GetHardwareCursorStats, frameCount:%{public}d, vsyncCount:%{public}d",
        frameCount, vsyncCount);
    napi_value frameNapiCount;
    CHKRP(napi_create_uint32(env, frameCount, &frameNapiCount), CREATE_UINT32);
    napi_value vsyncNapiCount;
    CHKRP(napi_create_uint32(env, vsyncCount, &vsyncNapiCount), CREATE_UINT32);
    status = napi_set_named_property(env, result, "frameCount", frameNapiCount);
    if (status != napi_ok) {
        MMI_HILOGE("Napi set frameCount named property is failed");
        return nullptr;
    }
    status = napi_set_named_property(env, result, "vsyncCount", vsyncNapiCount);
    if (status != napi_ok) {
        MMI_HILOGE("Napi set vsyncCount named property is failed");
        return nullptr;
    }
    return result;
}

napi_value JsPointerManager::SetTouchpadScrollRows(napi_env env, int32_t rows, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    asyncContext->errorCode = InputManager::GetInstance()->SetTouchpadScrollRows(rows);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
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

napi_value JsPointerManager::GetTouchpadScrollRows(napi_env env, napi_value handle)
{
    CALL_DEBUG_ENTER;
    sptr<AsyncContext> asyncContext = new (std::nothrow) AsyncContext(env);
    CHKPP(asyncContext);
    int32_t rows = TOUCHPAD_SCROLL_ROWS;
    asyncContext->errorCode = InputManager::GetInstance()->GetTouchpadScrollRows(rows);
    if (asyncContext->errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
        return nullptr;
    }
    asyncContext->reserve << ReturnType::NUMBER << rows;
    napi_value promise = nullptr;
    uint32_t initialRefCount = 1;
    if (handle != nullptr) {
        CHKRP(napi_create_reference(env, handle, initialRefCount, &asyncContext->callback), CREATE_REFERENCE);
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