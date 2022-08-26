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

#ifndef INPUT_DEVICE_COOPERATE_CONSTANTS_H
#define INPUT_DEVICE_COOPERATE_CONSTANTS_H

#include <cstddef>
#include <string_view>

namespace OHOS {
namespace MMI {
constexpr std::string_view CALL_FUNCTION = "napi_call_function";
constexpr std::string_view CREATE_STRING = "napi_create_string_utf8";
constexpr std::string_view CREATE_OBJECT = "napi_create_object";
constexpr std::string_view CREATE_INT32 = "napi_create_int32";
constexpr std::string_view CREATE_PROMISE = "napi_create_promise";
constexpr std::string_view CREATE_REFERENCE = "napi_create_reference";
constexpr std::string_view CREATE_ASYNC_WORK = "napi_create_async_work";
constexpr std::string_view DEFINE_PROPERTIES = "napi_define_properties";
constexpr std::string_view DEFINE_CLASS = "napi_define_class";
constexpr std::string_view DELETE_REFERENCE = "napi_delete_reference";
constexpr std::string_view GET_CB_INFO = "napi_get_cb_info";
constexpr std::string_view GET_BOOL = "napi_get_value_bool";
constexpr std::string_view GET_GLOBAL = "napi_get_global";
constexpr std::string_view GET_REFERENCE_VALUE = "napi_get_reference_value";
constexpr std::string_view GET_BOOLEAN = "napi_get_boolean";
constexpr std::string_view GET_INT32 = "napi_get_value_int32";
constexpr std::string_view GET_UV_LOOP = "napi_get_uv_event_loop";
constexpr std::string_view GET_UNDEFINED = "napi_get_undefined";
constexpr std::string_view GET_STRING = "napi_get_value_string_utf8";
constexpr std::string_view GET_NAMED_PROPERTY = "napi_get_named_property";
constexpr std::string_view HAS_NAMED_PROPERTY = "napi_has_named_property";
constexpr std::string_view NEW_INSTANCE = "napi_new_instance";
constexpr std::string_view QUEUE_ASYNC_WORK = "napi_queue_async_work";
constexpr std::string_view RESOLVE_DEFERRED = "napi_resolve_deferred";
constexpr std::string_view REJECT_DEFERRED = "napi_reject_deferred";
constexpr std::string_view REFERENCE_REF = "napi_reference_ref";
constexpr std::string_view SET_NAMED_PROPERTY = "napi_set_named_property";
constexpr std::string_view STRICT_EQUALS = "napi_strict_equals";
constexpr std::string_view TYPEOF = "napi_typeof";
constexpr std::string_view UNWRAP = "napi_unwrap";
constexpr std::string_view WRAP = "napi_wrap";

constexpr size_t MAX_STRING_LEN = 1024;

constexpr int SUCCESS = 0;
constexpr int FAILED = -1;
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_COOPERATE_CONSTANTS_H
