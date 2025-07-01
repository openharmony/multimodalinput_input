/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef JS_REGISTER_UTIL_H
#define JS_REGISTER_UTIL_H

#include "js_register_module.h"

namespace OHOS {
namespace MMI {
int32_t GetNamedPropertyBool(const napi_env& env, const napi_value& object, const std::string& name, bool& ret);
int32_t GetNamedPropertyInt32(const napi_env& env, const napi_value& object, const std::string& name,
    int32_t& ret, bool required = true);
int32_t GetNamedPropertyInt64(const napi_env& env, const napi_value& object, const std::string& name, int64_t& ret);
int32_t GetNamedPropertyDouble(const napi_env& env, const napi_value& object, const std::string& name, double& ret);
bool CheckType(const napi_env& env, const napi_value& value, const napi_valuetype& type);
bool IsArray(const napi_env& env, const napi_value& value);
bool ParseInt32(const napi_env& env, const napi_value& value, int32_t& result);
int32_t GetNamedPropertyArrayInt32(const napi_env& env, const napi_value& object, const std::string &name,
    std::vector<int32_t>& result);
int32_t GetNamedPropertyBoolOptional(const napi_env& env, const napi_value& object, const std::string& name,
    bool& ret);
} // namespace MMI
} // namespace OHOS
#endif // JS_REGISTER_UTIL_H