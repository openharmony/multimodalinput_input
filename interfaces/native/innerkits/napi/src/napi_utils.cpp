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

#include "napi_utils.h"
#include <iostream>

int32_t IsMatchType(napi_value value, napi_valuetype type, napi_env env)
{
    napi_valuetype paramType;
    napi_typeof(env, value, &paramType);
    if (paramType != type) {
        return EVENT_INVALID_PARAMETER;
    }
    return EVENT_OK;
}

napi_value GetNapiInt32_t(int32_t number, napi_env env)
{
    napi_value value;
    napi_create_int32(env, number, &value);
    return value;
}

int32_t GetCppInt32_t(napi_value value, napi_env env)
{
    int32_t number;
    napi_get_value_int32(env, value, &number);
    return number;
}

bool GetCppBool(napi_value value, napi_env env)
{
    bool number = false;
    napi_get_value_bool(env, value, &number);
    return number;
}

void EmitAsyncCallbackWork(napi_env env, AsyncCallbackInfo *asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        return;
    }
    napi_value resourceName;
    napi_create_string_latin1(env, "AsyncCallback", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName, [](napi_env env, void* data) {},
        [](napi_env env, napi_status status, void* data) {
            AsyncCallbackInfo *asyncCallbackInfo = (AsyncCallbackInfo *)data;
            napi_value callback;
            napi_get_reference_value(env, asyncCallbackInfo->callback[0], &callback);
            napi_call_function(env, nullptr, callback, 1, &asyncCallbackInfo->callbackData, nullptr);
            napi_delete_reference(env, asyncCallbackInfo->callback[0]);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void*)asyncCallbackInfo, &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
}

void EmitPromiseWork(napi_env env, AsyncCallbackInfo *asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        return;
    }
    napi_value resourceName;
    napi_create_string_latin1(env, "Promise", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName, [](napi_env env, void* data) {},
        [](napi_env env, napi_status status, void* data) {
            AsyncCallbackInfo *asyncCallbackInfo = (AsyncCallbackInfo *)data;
            napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, asyncCallbackInfo->callbackData);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void*)asyncCallbackInfo, &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
}