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
struct AsyncContext {
    napi_env env;
    napi_async_work work;
    napi_ref ref = nullptr;
    napi_deferred deferred;
    napi_status status;
};

struct PointerAsyncContext : AsyncContext {
    bool visible = true;
};
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
    auto asyncContext = new(std::nothrow) PointerAsyncContext();
    if (asyncContext == nullptr) {
        napi_throw_error(env, nullptr, "Create PointerAsyncContext failed");
        return nullptr;
    }
    asyncContext->env = env;
    asyncContext->visible = visible;
    if (handle != nullptr) {
        CHKRP(env, napi_create_reference(env, handle, 1, &asyncContext->ref), CREATE_REFERENCE);
    }

    napi_value promise = nullptr;
    if (asyncContext->ref == nullptr) {
        CHKRP(env, napi_create_promise(env, &asyncContext->deferred, &promise), CREATE_PROMISE);
    } else {
        CHKRP(env, napi_get_undefined(env, &promise), GET_UNDEFINED);
    }

    napi_value resource = nullptr;
    CHKRP(env, napi_create_string_utf8(env, "SetPointerVisible", NAPI_AUTO_LENGTH, &resource), CREATE_STRING_UTF8);
    napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
            PointerAsyncContext* asyncContext = (PointerAsyncContext*)data;
            int32_t ret = InputManager::GetInstance()->SetPointerVisible(asyncContext->visible);
            if (ret == RET_OK) {
                asyncContext->status = napi_ok;
            } else {
                asyncContext->status = napi_generic_failure;
            }
        }, [](napi_env env, napi_status status, void* data) {
            PointerAsyncContext* asyncContext = (PointerAsyncContext*)data;
            napi_value result = nullptr;
            CHKRV(env, napi_get_undefined(env, &result), GET_UNDEFINED);
            if (asyncContext->deferred) {
                if (asyncContext->status == napi_ok) {
                    CHKRV(env, napi_resolve_deferred(env, asyncContext->deferred, result), RESOLVE_DEFERRED);
                } else {
                    CHKRV(env, napi_reject_deferred(env, asyncContext->deferred, result), REJECT_DEFERRED);
                }
            } else {
                napi_value handlerTemp = nullptr;
                CHKRV(env, napi_get_reference_value(env, asyncContext->ref, &handlerTemp), GET_REFERENCE);
                napi_value callResult = nullptr;
                CHKRV(env, napi_call_function(env, nullptr, handlerTemp, 1, &result, &callResult), CALL_FUNCTION);
                CHKRV(env, napi_delete_reference(env, asyncContext->ref), "napi_delete_reference");
            }
            napi_delete_async_work(env, asyncContext->work);
            delete asyncContext;
        }, (void*)asyncContext, &asyncContext->work);
    napi_queue_async_work(env, asyncContext->work);
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