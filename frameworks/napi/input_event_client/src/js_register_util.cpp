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

#include "js_register_module.h"
#include "napi_constants.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JSRegisterUtil"

namespace OHOS {
namespace MMI {
int32_t GetNamedPropertyBool(const napi_env& env, const napi_value& object, const std::string& name, bool& ret)
{
    napi_value napiValue = {};
    CHKRF(napi_get_named_property(env, object, name.c_str(), &napiValue), GET_NAMED_PROPERTY);
    if (napiValue == nullptr) {
        MMI_HILOGE("The value is null");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid KeyEvent");
        return RET_ERR;
    }
    napi_valuetype tmpType = napi_undefined;
    CHKRF(napi_typeof(env, napiValue, &tmpType), TYPEOF);
    if (tmpType != napi_boolean) {
        MMI_HILOGE("The name is not bool");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, name.c_str(), "bool");
        return RET_ERR;
    }
    CHKRF(napi_get_value_bool(env, napiValue, &ret), GET_VALUE_BOOL);
    return RET_OK;
}

int32_t GetNamedPropertyInt32(const napi_env& env, const napi_value& object,
    const std::string& name, int32_t& ret, bool required)
{
    napi_value napiValue = {};
    if (napi_get_named_property(env, object, name.c_str(), &napiValue) != napi_ok) {
        MMI_HILOGE("Call napi_get_named_property failed");
        return RET_ERR;
    }
    if (napiValue == nullptr) {
        MMI_HILOGE("The value is null");
        if (required) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid KeyEvent");
        }
        return RET_ERR;
    }
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        return RET_ERR;
    }
    if (tmpType != napi_number) {
        MMI_HILOGE("The value is not int32_t");
        if (required) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid KeyEvent");
        }
        return RET_ERR;
    }
    if (napi_get_value_int32(env, napiValue, &ret) != napi_ok) {
        MMI_HILOGE("NapiElement get int32 value failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t GetNamedPropertyInt64(const napi_env& env, const napi_value& object, const std::string& name, int64_t& ret)
{
    napi_value napiValue = {};
    if (napi_get_named_property(env, object, name.c_str(), &napiValue) != napi_ok) {
        MMI_HILOGE("Call napi_get_named_property failed");
        return RET_ERR;
    }
    if (napiValue == nullptr) {
        MMI_HILOGE("The value is null");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid KeyEvent");
        return RET_ERR;
    }
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        return RET_ERR;
    }
    if (tmpType != napi_number) {
        MMI_HILOGE("The value is not int64_t");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, name.c_str(), "int");
        return RET_ERR;
    }
    if (napi_get_value_int64(env, napiValue, &ret) != napi_ok) {
        MMI_HILOGE("NapiElement get int64 value failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t GetNamedPropertyDouble(const napi_env& env, const napi_value& object, const std::string& name, double& ret)
{
    napi_value napiValue = {};
    if (napi_get_named_property(env, object, name.c_str(), &napiValue) != napi_ok) {
        MMI_HILOGE("Call napi_get_named_property failed");
        return RET_ERR;
    }
    if (napiValue == nullptr) {
        MMI_HILOGE("The value is null");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid value");
        return RET_ERR;
    }
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        return RET_ERR;
    }
    if (tmpType != napi_number) {
        MMI_HILOGE("The value is not double");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, name.c_str(), "double");
        return RET_ERR;
    }
    if (napi_get_value_double(env, napiValue, &ret) != napi_ok) {
        MMI_HILOGE("NapiElement get double value failed");
        return RET_ERR;
    }
    return RET_OK;
}

bool CheckType(const napi_env& env, const napi_value& value, const napi_valuetype& type)
{
    napi_valuetype valuetype = napi_undefined;
    napi_typeof(env, value, &valuetype);
    if (valuetype != type) {
        return false;
    }
    return true;
}

bool IsArray(const napi_env& env, const napi_value& value)
{
    bool isArray = false;
    if (napi_is_array(env, value, &isArray) != napi_ok) {
        MMI_HILOGE("napi_is_array failed");
        return false;
    }
    return isArray;
}

bool ParseInt32(const napi_env& env, const napi_value& value, int32_t& result)
{
    if (!CheckType(env, value, napi_number)) {
        MMI_HILOGE("ParseInt32 type not number");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "element of pattern", "Number");
        return false;
    }
    if (napi_get_value_int32(env, value, &result) != napi_ok) {
        MMI_HILOGE("napi_get_value_int32 failed");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "element of pattern", "Int32");
        return false;
    }
    return true;
}

int32_t GetNamedPropertyArrayInt32(const napi_env& env, const napi_value& object, const std::string& name,
    std::vector<int32_t>& result)
{
    napi_value napiValue = {};
    if (napi_get_named_property(env, object, name.c_str(), &napiValue) != napi_ok) {
        MMI_HILOGE("Call napi_get_named_property failed, name:%{public}s", name.c_str());
        return RET_ERR;
    }
    if (napiValue == nullptr) {
        MMI_HILOGE("The value is null");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid value");
        return RET_ERR;
    }
    if (!IsArray(env, napiValue)) {
        MMI_HILOGE("Current obj is not array");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "pattern", "Array");
        return RET_ERR;
    }
    uint32_t length = 0;
    napi_get_array_length(env, napiValue, &length);
    for (uint32_t i = 0; i < length; i++) {
        napi_value arrayElem = nullptr;
        if (napi_get_element(env, napiValue, i, &arrayElem) != napi_ok) {
            MMI_HILOGE("napi_get_element failed, index:%{public}d", i);
            return RET_ERR;
        }
        int32_t res = { -1 };
        if (!ParseInt32(env, arrayElem, res)) {
            MMI_HILOGE("parse array elem fail, index:%{public}d", i);
            THROWERR_API9(env, COMMON_PARAMETER_ERROR, "element of pattern", "Int32");
            return RET_ERR;
        }
        if (res < 0) {
            THROWERR_API9(env, COMMON_PARAMETER_ERROR, "value for element of pattern", "must be positive");
            return RET_ERR;
        }
        result.emplace_back(res);
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
