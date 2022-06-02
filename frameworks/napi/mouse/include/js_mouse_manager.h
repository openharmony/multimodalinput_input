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

#ifndef JS_MOUSE_MANAGER_H
#define JS_MOUSE_MANAGER_H

#include <memory>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "util_napi.h"
#include "utils/log.h"
#include "refbase.h"

#include "stream_buffer.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager.h"

namespace OHOS {
namespace MMI {
namespace {
const std::string GET_BOOL = "napi_get_boolean";
const std::string DELETE_REFERENCE = "napi_delete_reference";
const std::string DELETE_ASYNC_WORK = "napi_delete_async_work";
const std::string TYPEOF = "napi_typeof";
const std::string GET_GLOBLE = "napi_get_global";
const std::string DEFINE_CLASS = "napi_define_class";
const std::string WRAP = "napi_wrap";
const std::string UNWRAP = "napi_unwrap";
const std::string NEW_INSTANCE = "napi_new_instance";
const std::string SET_NAMED_PROPERTY = "napi_set_named_property";
const std::string CREATE_REFERENCE = "napi_create_reference";
const std::string REFERENCE_REF = "napi_create_reference";
const std::string GET_CB_INFO = "napi_get_cb_info";
const std::string HAS_NAMED_PROPERTY = "napi_has_named_property";
const std::string DEFINE_PROPERTIES = "napi_define_properties";
const std::string CREATE_PROMISE = "napi_create_promise";
const std::string CREATE_STRING_UTF8 = "napi_create_string_utf8";
const std::string GET_UNDEFINED = "napi_get_undefined";
const std::string RESOLVE_DEFERRED = "napi_resolve_deferred";
const std::string REJECT_DEFERRED = "napi_reject_deferred";
const std::string GET_REFERENCE = "napi_get_reference_value";
const std::string CALL_FUNCTION = "napi_call_function";
const std::string CREATE_BOOL = "napi_get_boolean";
const std::string CREATE_INT32 = "napi_create_int32";
} // namespace

class JsCommon {
public:
    static bool TypeOf(napi_env env, napi_value value, napi_valuetype type);
};

struct AsyncContext : RefBase {
    napi_env env = nullptr;
    napi_async_work work = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;
    int32_t errorCode {-1};
    StreamBuffer reserve;
    AsyncContext(napi_env env) : env(env) {}
    ~AsyncContext();
};

class JsMouseManager {
public:
    JsMouseManager() = default;
    ~JsMouseManager() = default;
    DISALLOW_COPY_AND_MOVE(JsMouseManager);

    void ResetEnv();
    napi_value SetPointerVisible(napi_env env, bool visible, napi_value handle = nullptr);
    napi_value IsPointerVisible(napi_env env, napi_value handle = nullptr);
};
} // namespace MMI
} // namespace OHOS

#endif // JS_MOUSE_MANAGER_H