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

#include "napi/native_api.h"
#include "napi/native_node_api.h"

struct AsyncCallbackInfo {
    napi_env env;
    napi_async_work asyncWork;
    napi_deferred deferred;
    napi_ref callback[1] = { 0 };
    napi_value callbackData;
};

#define EVENT_INVALID_PARAMETER (-1);
#define EVENT_OK 0;
int32_t IsMatchType(napi_value value, napi_valuetype type, napi_env env);
napi_value GetNapiInt32_t(int32_t number, napi_env env);
int32_t GetCppInt32_t(napi_value value, napi_env env);
bool GetCppBool(napi_value value, napi_env env);
void EmitAsyncCallbackWork(napi_env env, AsyncCallbackInfo *async_callback_info);
void EmitPromiseWork(napi_env env, AsyncCallbackInfo *asyncCallbackInfo);

