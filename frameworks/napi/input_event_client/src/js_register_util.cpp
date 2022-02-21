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
#include "js_register_util.h"
#include "js_register_module.h"
#include <cinttypes>

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterUtil" };
    constexpr size_t MAX_STRING_LEN = 1024;
}

void SetNamedProperty(const napi_env& env, napi_value object, const std::string& name, bool value)
{
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_int32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}d failed", name.c_str(), value);
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env& env, napi_value object, const std::string& name, uint16_t value)
{
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_uint32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}u failed", name.c_str(), value);
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env& env, napi_value object, const std::string& name, uint32_t value)
{
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_uint32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}u failed", name.c_str(), value);
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env& env, napi_value object, const std::string& name, int32_t value)
{
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_int32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}d failed", name.c_str(), value);
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env& env, napi_value object, const std::string& name, float value)
{
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_double(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}f failed", name.c_str(), value);
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env& env, napi_value object, const std::string& name, double value)
{
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_double(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}lf failed", name.c_str(), value);
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env& env, napi_value object, const std::string& name, uint64_t value)
{
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_int64(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}" PRId64 " failed", name.c_str(), value);
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env& env, napi_value object, const std::string& name, std::string value)
{
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &napiValue);
    if (status != napi_ok) {
        MMI_LOGE("%{public}s=%{public}s failed", name.c_str(), value.c_str());
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), napiValue));
}

void SetNamedProperty(const napi_env& env, napi_value object, const std::string& name, napi_value value)
{
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name.c_str(), value));
}

bool GetNamedPropertyBool(const napi_env& env, const napi_value& object, const std::string& name)
{
    bool value = false;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGE("call napi_typeof fail");
        return false;
    }
    if (tmpType != napi_boolean) {
        MMI_LOGE("value is not bool");
        return value;
    }

    napi_get_value_bool(env, napiValue, &value);
    return value;
}

std::string GetNamedPropertyString(const napi_env& env, const napi_value& object, const std::string& name)
{
    std::string value = "";
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGE("call napi_typeof fail");
        return value;
    }
    if (tmpType != napi_string) {
        MMI_LOGE("value is not bool");
        return value;
    }

    char tmpValue[MAX_STRING_LEN] = { 0 };
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, napiValue, tmpValue, MAX_STRING_LEN - 1, &typeLen);
    value = tmpValue;
    return value;
}

int32_t GetNamedPropertyInt32(const napi_env& env, const napi_value& object, const std::string& name)
{
    int32_t value = 0;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGE("call napi_typeof fail");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_LOGE("value is not number");
        return value;
    }
    napi_get_value_int32(env, napiValue, &value);
    return value;
}

int64_t GetNamedPropertyInt64(const napi_env& env, const napi_value& object, const std::string& name)
{
    int64_t value = 0;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGE("call napi_typeof fail");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_LOGE("value is not number");
        return value;
    }
    napi_get_value_int64(env, napiValue, &value);
    return value;
}

uint32_t GetNamedPropertyUint32(const napi_env& env, const napi_value& object, const std::string& name)
{
    uint32_t value = 0;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGE("call napi_typeof fail");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_LOGE("value is not number");
        return value;
    }
    napi_get_value_uint32(env, napiValue, &value);
    return value;
}
} // namespace MMI
} // namespace OHOS

