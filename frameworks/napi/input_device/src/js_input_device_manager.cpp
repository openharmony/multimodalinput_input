/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "js_input_device_manager.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputDeviceManager" };
std::mutex mutex_;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
const std::string CREATE_PROMISE = "napi_create_promise";
const std::string CREATE_STRING_UTF8 = "napi_create_string_utf8";
const std::string GET_UNDEFINED = "napi_get_undefined";
const std::string RESOLVE_DEFERRED = "napi_resolve_deferred";
const std::string REJECT_DEFERRED = "napi_reject_deferred";
const std::string CREATE_REFERENCE = "napi_create_reference";
const std::string GET_REFERENCE = "napi_get_reference_value";
const std::string CALL_FUNCTION = "napi_call_function";
#endif
} // namespace

JsInputDeviceManager::JsInputDeviceManager()
{
    CALL_LOG_ENTER;
    InputDevImp.RegisterInputDeviceMonitor(TargetOn);
}

JsInputDeviceManager::~JsInputDeviceManager() {}

void JsInputDeviceManager::RegisterInputDeviceMonitor(napi_env env, std::string type, napi_value handle)
{
    CALL_LOG_ENTER;
    AddMonitor(env, type, handle);
}

void JsInputDeviceManager::UnRegisterInputDeviceMonitor(napi_env env, std::string type, napi_value handle)
{
    CALL_LOG_ENTER;
    RemoveMonitor(env, type, handle);
}

napi_value JsInputDeviceManager::GetDeviceIds(napi_env env, napi_value handle)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t userData = InputDevImp.GetUserData();
    napi_value ret = CreateCallbackInfo(env, handle, userData);
    InputDevImp.GetInputDeviceIdsAsync(EmitJsIds);
    return ret;
}

napi_value JsInputDeviceManager::GetDevice(napi_env env, int32_t id, napi_value handle)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t userData = InputDevImp.GetUserData();
    napi_value ret = CreateCallbackInfo(env, handle, userData);
    InputDevImp.GetInputDeviceAsync(id, EmitJsDev);
    return ret;
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
napi_value JsInputDeviceManager::SetPointerVisible(napi_env env, bool visible, napi_value handle)
{
    CALL_LOG_ENTER;
    sptr<JsUtil::PointerAsyncContext> asyncContext = new (std::nothrow) JsUtil::PointerAsyncContext(env);
    if (asyncContext == nullptr) {
        THROWERR(env, "create PointerAsyncContext failed");
        return nullptr;
    }
    asyncContext->visible = visible;
    napi_value promise = nullptr;
    if (handle == nullptr) {
        CHKRP(env, napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    } else {
        CHKRP(env, napi_get_undefined(env, &promise), GET_UNDEFINED);
    }

    napi_value resource = nullptr;
    CHKRP(env, napi_create_string_utf8(env, "setPointerVisible", NAPI_AUTO_LENGTH, &resource), CREATE_STRING_UTF8);
    if (handle != nullptr || napi_create_reference(env, handle, 1, &asyncContext->callback) != napi_ok ) {
        asyncContext->contextInfo = nullptr;
        return nullptr;
    }

    asyncContext->contextInfo = asyncContext;
    napi_status status = napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
            JsUtil::PointerAsyncContext* asyncContext = static_cast<JsUtil::PointerAsyncContext*>(data);
            asyncContext->errorCode = InputManager::GetInstance()->SetPointerVisible(asyncContext->visible);
        }, [](napi_env env, napi_status status, void* data) {
            CHKPV(data);
            sptr<JsUtil::PointerAsyncContext> asyncContext = reinterpret_cast<JsUtil::PointerAsyncContext *>(data)->contextInfo;
            asyncContext->contextInfo = nullptr;
            napi_value result = nullptr;
            CHKRV(env, napi_get_undefined(env, &result), GET_UNDEFINED);
            if (asyncContext->deferred) {
                if (asyncContext->errorCode == RET_OK) {
                    CHKRV(env, napi_resolve_deferred(env, asyncContext->deferred, result), RESOLVE_DEFERRED);
                } else {
                    CHKRV(env, napi_reject_deferred(env, asyncContext->deferred, result), REJECT_DEFERRED);
                }
            } else {
                napi_value handlerTemp = nullptr;
                CHKRV(env, napi_get_reference_value(env, asyncContext->callback, &handlerTemp), GET_REFERENCE);
                napi_value callResult = nullptr;
                CHKRV(env, napi_call_function(env, nullptr, handlerTemp, 1, &result, &callResult), CALL_FUNCTION);
                CHKRV(env, napi_delete_reference(env, asyncContext->callback), "napi_delete_reference");
            }
        }, asyncContext.GetRefPtr(), &asyncContext->work);
    if (status != napi_ok || napi_queue_async_work(env, asyncContext->work) != napi_ok) {
        MMI_HILOGE("create async work fail");
        asyncContext->contextInfo = nullptr;
    }
    return promise;
}
#endif

napi_value JsInputDeviceManager::GetKeystrokeAbility(napi_env env, int32_t id, std::vector<int32_t> keyCodes,
                                                     napi_value handle)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    int32_t userData = InputDevImp.GetUserData();
    napi_value ret = CreateCallbackInfo(env, handle, userData);
    InputDevImp.GetKeystrokeAbility(id, keyCodes, EmitJsKeystrokeAbility);
    return ret;
}

void JsInputDeviceManager::ResetEnv()
{
    CALL_LOG_ENTER;
    InputDevImp.UnRegisterInputDeviceMonitor();
    JsEventTarget::ResetEnv();
}
} // namespace MMI
} // namespace OHOS