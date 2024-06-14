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

#ifndef NAPI_CONSTANTS_H
#define NAPI_CONSTANTS_H

#include <cstddef>
#include <string_view>

namespace OHOS {
namespace MMI {
inline constexpr std::string_view CALL_FUNCTION = "napi_call_function";
inline constexpr std::string_view CREATE_OBJECT = "napi_create_object";
inline constexpr std::string_view CREATE_INT32 = "napi_create_int32";
inline constexpr std::string_view CREATE_UINT32 = "napi_create_uint32";
inline constexpr std::string_view CREATE_PROMISE = "napi_create_promise";
inline constexpr std::string_view CREATE_REFERENCE = "napi_create_reference";
inline constexpr std::string_view CREATE_ASYNC_WORK = "napi_create_async_work";
inline constexpr std::string_view DEFINE_PROPERTIES = "napi_define_properties";
inline constexpr std::string_view DEFINE_CLASS = "napi_define_class";
inline constexpr std::string_view DELETE_REFERENCE = "napi_delete_reference";
inline constexpr std::string_view GET_CB_INFO = "napi_get_cb_info";
inline constexpr std::string_view GET_VALUE_BOOL = "napi_get_value_bool";
inline constexpr std::string_view GET_GLOBAL = "napi_get_global";
inline constexpr std::string_view GET_REFERENCE_VALUE = "napi_get_reference_value";
inline constexpr std::string_view GET_BOOLEAN = "napi_get_boolean";
inline constexpr std::string_view GET_VALUE_INT32 = "napi_get_value_int32";
inline constexpr std::string_view GET_UV_EVENT_LOOP = "napi_get_uv_event_loop";
inline constexpr std::string_view GET_UNDEFINED = "napi_get_undefined";
inline constexpr std::string_view GET_NAMED_PROPERTY = "napi_get_named_property";
inline constexpr std::string_view HAS_NAMED_PROPERTY = "napi_has_named_property";
inline constexpr std::string_view NEW_INSTANCE = "napi_new_instance";
inline constexpr std::string_view QUEUE_ASYNC_WORK = "napi_queue_async_work";
inline constexpr std::string_view RESOLVE_DEFERRED = "napi_resolve_deferred";
inline constexpr std::string_view REJECT_DEFERRED = "napi_reject_deferred";
inline constexpr std::string_view REFERENCE_REF = "napi_reference_ref";
inline constexpr std::string_view REFERENCE_UNREF = "napi_reference_unref";
inline constexpr std::string_view SET_NAMED_PROPERTY = "napi_set_named_property";
inline constexpr std::string_view STRICT_EQUALS = "napi_strict_equals";
inline constexpr std::string_view TYPEOF = "napi_typeof";
inline constexpr std::string_view UNWRAP = "napi_unwrap";
inline constexpr std::string_view WRAP = "napi_wrap";
inline constexpr std::string_view GET_VALUE_STRING_UTF8 = "napi_get_value_string_utf8";
inline constexpr std::string_view GET_ARRAY_LENGTH = "napi_get_array_length";
inline constexpr std::string_view GET_ELEMENT = "napi_get_element";
inline constexpr std::string_view CREATE_ARRAY = "napi_create_array";
inline constexpr std::string_view SET_ELEMENT = "napi_set_element";
inline constexpr std::string_view CREATE_STRING_UTF8 = "napi_create_string_utf8";
inline const std::string CHANGED_TYPE = "change";
inline const std::string SUBSCRIBE_TYPE = "key";
inline constexpr std::string_view DELETE_ASYNC_WORK = "napi_delete_async_work";
inline constexpr std::string_view COERCE_TO_BOOL = "napi_coerce_to_bool";
inline constexpr std::string_view CREATE_ERROR = "napi_create_error";

inline constexpr size_t MAX_STRING_LEN { 1024 };

inline constexpr int SUCCESS { 0 };
inline constexpr int FAILED { -1 };
inline constexpr int32_t ANR_DISPATCH = 0;
inline constexpr int32_t ANR_MONITOR = 1;

inline constexpr uint32_t EVDEV_UDEV_TAG_KEYBOARD = (1 << 1);
inline constexpr uint32_t EVDEV_UDEV_TAG_MOUSE = (1 << 2);
inline constexpr uint32_t EVDEV_UDEV_TAG_TOUCHPAD = (1 << 3);
} // namespace MMI
} // namespace OHOS
#endif // NAPI_CONSTANTS_H
