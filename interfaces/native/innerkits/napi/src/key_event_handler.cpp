/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "key_event_handler.h"

static napi_value InjectEvent(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_value thisArg = nullptr;
    void* data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thisArg, &data));
    napi_value eventObject = args[0];
    int32_t ret = IsMatchType(eventObject, napi_object, env);
    AsyncCallbackInfo *asyncCallbackInfo = new AsyncCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
    };
    if (argc >= 1) {
        napi_create_reference(env, args[1], 1, &asyncCallbackInfo->callback[0]);
        if (ret != 0) {
            asyncCallbackInfo->callbackData = GetNapiInt32_t(-1, env);
            EmitAsyncCallbackWork(env, asyncCallbackInfo);
            napi_value undefined;
            napi_get_undefined(env, &undefined);
            return undefined;
        }
        napi_value isPressed, keyCode, keyDownDuration;
        napi_get_named_property(env, eventObject, "isPressed", &isPressed);
        napi_get_named_property(env, eventObject, "keyDownDuration", &keyDownDuration);
        napi_get_named_property(env, eventObject, "keyCode", &keyCode);
        if (IsMatchType(isPressed, napi_boolean, env) || IsMatchType(keyCode, napi_number, env)
            || IsMatchType(keyDownDuration, napi_number, env)) {
            asyncCallbackInfo->callbackData = GetNapiInt32_t(-1, env);
            EmitAsyncCallbackWork(env, asyncCallbackInfo);
            napi_value undefined;
            napi_get_undefined(env, &undefined);
            return undefined;
        }
        OHOS::KeyProperty keyProperty = {
            .isPressed = GetCppBool(isPressed, env),
            .keyCode = GetCppInt32_t(keyCode, env),
            .keyDownDuration = GetCppInt32_t(keyDownDuration, env),
        };
        OHOS::MultimodalProperty multimodalProperty {
            .highLevelEvent = 1,
            .uuid = "11111",
            .sourceType = 1,
            .occurredTime = 1,
            .deviceId = "11111",
            .inputDeviceId = 1,
            .isHighLevelEvent = true,
        };
        OHOS::sptr<OHOS::KeyEvent> event = new OHOS::KeyEvent();
        event->Initialize(multimodalProperty, keyProperty);
        std::shared_ptr<OHOS::InjectManager> injectManager = OHOS::InjectManager::GetInstance();
        bool isSucceed = injectManager->InjectEvent(event);
        if (!isSucceed) {
            asyncCallbackInfo->callbackData = GetNapiInt32_t(-1, env);
            EmitAsyncCallbackWork(env, asyncCallbackInfo);
            napi_value undefined;
            napi_get_undefined(env, &undefined);
            return undefined;
        }
        asyncCallbackInfo->callbackData = GetNapiInt32_t(0, env);
        EmitAsyncCallbackWork(env, asyncCallbackInfo);
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    } else {
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;
        if (ret != 0) {
            asyncCallbackInfo->callbackData = GetNapiInt32_t(-1, env);
            EmitPromiseWork(env, asyncCallbackInfo);
            napi_value undefined;
            napi_get_undefined(env, &undefined);
            return undefined;
        }
        napi_value isPressed, keyCode, keyDownDuration;
        napi_get_named_property(env, eventObject, "isPressed", &isPressed);
        napi_get_named_property(env, eventObject, "keyDownDuration", &keyDownDuration);
        napi_get_named_property(env, eventObject, "keyCode", &keyCode);
        if (IsMatchType(isPressed, napi_boolean, env) || IsMatchType(keyCode, napi_number, env)
            || IsMatchType(keyDownDuration, napi_number, env)) {
            asyncCallbackInfo->callbackData = GetNapiInt32_t(-1, env);
            EmitPromiseWork(env, asyncCallbackInfo);
            napi_value undefined;
            napi_get_undefined(env, &undefined);
            return undefined;
        }
        OHOS::KeyProperty keyProperty = {
            .isPressed = GetCppBool(isPressed, env),
            .keyCode = GetCppInt32_t(keyCode, env),
            .keyDownDuration = GetCppInt32_t(keyDownDuration, env),
        };
        OHOS::MultimodalProperty multimodalProperty {
            .highLevelEvent = 1,
            .uuid = "11111",
            .sourceType = 1,
            .occurredTime = 1,
            .deviceId = "11111",
            .inputDeviceId = 1,
            .isHighLevelEvent = true,
        };
        OHOS::sptr<OHOS::KeyEvent> event = new OHOS::KeyEvent();
        event->Initialize(multimodalProperty, keyProperty);
        std::shared_ptr<OHOS::InjectManager> injectManager = OHOS::InjectManager::GetInstance();
        bool isSucceed = injectManager->InjectEvent(event);
        if (!isSucceed) {
            asyncCallbackInfo->callbackData = GetNapiInt32_t(-1, env);
            EmitPromiseWork(env, asyncCallbackInfo);
            napi_value undefined;
            napi_get_undefined(env, &undefined);
            return undefined;
        }
        asyncCallbackInfo->callbackData = GetNapiInt32_t(0, env);
        EmitPromiseWork(env, asyncCallbackInfo);
        return promise;
    }
}

static napi_value InjectEventSync(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value args[2] = { 0 };
    napi_value thisArg = nullptr;
    void* data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, &thisArg, &data));
    napi_value eventObject = args[0];
    int32_t ret = IsMatchType(eventObject, napi_object, env);
    if (ret) {
        return GetNapiInt32_t(ret, env);
    }
    napi_value isPressed, keyCode, keyDownDuration;
    napi_get_named_property(env, eventObject, "isPressed", &isPressed);
    napi_get_named_property(env, eventObject, "keyDownDuration", &keyDownDuration);
    napi_get_named_property(env, eventObject, "keyCode", &keyCode);
    if (IsMatchType(isPressed, napi_boolean, env) || IsMatchType(keyCode, napi_number, env)
        || IsMatchType(keyDownDuration, napi_number, env)) {
        return GetNapiInt32_t(-1, env);
    }
    OHOS::KeyProperty keyProperty = {
        .isPressed = GetCppBool(isPressed, env),
        .keyCode = GetCppInt32_t(keyCode, env),
        .keyDownDuration = GetCppInt32_t(keyDownDuration, env),
    };
    OHOS::MultimodalProperty multimodalProperty {
        .highLevelEvent = 1,
        .uuid = "11111",
        .sourceType = 1,
        .occurredTime = 1,
        .deviceId = "11111",
        .inputDeviceId = 1,
        .isHighLevelEvent = true,
    };
    OHOS::sptr<OHOS::KeyEvent> event = new OHOS::KeyEvent();
    if (!event) {
        return GetNapiInt32_t(-1, env);
    }
    event->Initialize(multimodalProperty, keyProperty);
    std::shared_ptr<OHOS::InjectManager> injectManager = OHOS::InjectManager::GetInstance();
    bool isSucceed = injectManager->InjectEvent(event);
    if (!isSucceed) {
        return GetNapiInt32_t(-1, env);
    }
    return GetNapiInt32_t(0, env);
}

EXTERN_C_START

static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("injectEvent", InjectEvent),
        DECLARE_NAPI_FUNCTION("injectEventSync", InjectEventSync)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
EXTERN_C_END

static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "injectEventHandler",
    .nm_priv = ((void*)0),
    .reserved = { 0 }
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}
