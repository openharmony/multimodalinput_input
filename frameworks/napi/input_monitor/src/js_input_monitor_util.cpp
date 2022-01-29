/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "js_input_monitor_util.h"
#include <cinttypes>
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputMonitorUtil" };
    constexpr uint32_t MAX_STRING_LEN = 1024;
}

napi_status SetNameProperty(const napi_env& env, napi_value object, const std::string& name, bool value)
{
    MMI_LOGD("SetNameProperty: %{public}s=%{public}d", name.c_str(), value);
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_int32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGD("SetNameProperty %{public}s=%{public}d failed.", name.c_str(), value);
        return status;
    }
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    return status;
}

napi_status SetNameProperty(const napi_env& env, napi_value object, const std::string& name, uint16_t value)
{
    MMI_LOGD("SetNameProperty: %{public}s=%{public}u", name.c_str(), value);
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_uint32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGD("SetNameProperty: %{public}s=%{public}u failed.", name.c_str(), value);
        return status;
    }
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    return status;
}

napi_status SetNameProperty(const napi_env& env, napi_value object, const std::string& name, uint32_t value)
{
    MMI_LOGD("SetNameProperty: %{public}s=%{public}u", name.c_str(), value);
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_uint32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGD("SetNameProperty: %{public}s=%{public}u failed.", name.c_str(), value);
        return status;
    }
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    return status;
}

napi_status SetNameProperty(const napi_env& env, napi_value object, const std::string& name, int32_t value)
{
    MMI_LOGD("SetNameProperty: %{public}s=%{public}d", name.c_str(), value);
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_int32(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGD("SetNameProperty: %{public}s=%{public}d failed.", name.c_str(), value);
        return status;
    }
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    return status;
}

napi_status SetNameProperty(const napi_env& env, napi_value object, const std::string& name, float value)
{
    MMI_LOGD("SetNameProperty: %{public}s=%{public}f", name.c_str(), value);
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_double(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGD("SetNameProperty: %{public}s=%{public}f failed.", name.c_str(), value);
        return status;
    }
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    return status;
}

napi_status SetNameProperty(const napi_env& env, napi_value object, const std::string& name, double value)
{
    MMI_LOGD("SetNameProperty: %{public}s=%{public}lf", name.c_str(), value);
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_double(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGD("SetNameProperty: %{public}s=%{public}lf failed.", name.c_str(), value);
        return status;
    }
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    return status;
}

napi_status SetNameProperty(const napi_env& env, napi_value object, const std::string& name, uint64_t value)
{
    MMI_LOGD("SetNameProperty: %{public}s=%{public}" PRId64 "", name.c_str(), value);
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_int64(env, value, &napiValue);
    if (status != napi_ok) {
        MMI_LOGD("SetNameProperty: %{public}s=%{public}" PRId64 " failed.", name.c_str(), value);
        return status;
    }
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    return status;
}

napi_status SetNameProperty(const napi_env& env, napi_value object, const std::string& name, std::string value)
{
    MMI_LOGD("SetNameProperty: %{public}s=%{public}s", name.c_str(), value.c_str());
    napi_status status;
    napi_value napiValue = nullptr;
    status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &napiValue);
    if (status != napi_ok) {
        MMI_LOGD("SetNameProperty: %{public}s=%{public}s failed.", name.c_str(), value.c_str());
        return status;
    }
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    return status;
}

napi_status SetNameProperty(const napi_env& env, napi_value object, const std::string& name, napi_value value)
{
    MMI_LOGD("SetNameProperty: object=%{public}s", name.c_str());
    auto status = napi_set_named_property(env, object, name.c_str(), value);
    return status;
}

bool GetNamePropertyBool(const napi_env& env, const napi_value& object, const std::string& name)
{
    bool value = false;
    napi_value napiValue = {};
    napi_valuetype tmpType = napi_undefined;
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGD("GetNamePropertyBool: call napi_typeof fail.");
        return false;
    }
    if (tmpType != napi_boolean) {
        MMI_LOGD("GetNamePropertyBool: value is not bool");
        return value;
    }

    napi_get_value_bool(env, napiValue, &value);
    MMI_LOGD("GetNamePropertyBool: %{public}s=%{public}d", name.c_str(), value);
    return value;
}

std::string GetNamePropertyString(const napi_env& env, const napi_value& object, const std::string& name)
{
    std::string value = "";
    napi_value napiValue = {};
    napi_valuetype tmpType = napi_undefined;
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGD("GetNamePropertyString: call napi_typeof fail.");
        return value;
    }
    if (tmpType != napi_string) {
        MMI_LOGD("GetNamePropertyString: value is not bool");
        return value;
    }

    char tmpValue[MAX_STRING_LEN] = { 0 };
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, napiValue, tmpValue, MAX_STRING_LEN - 1, &typeLen);
    value = tmpValue;
    MMI_LOGD("GetNamePropertyString: %{public}s=%{public}s", name.c_str(), value.c_str());
    return value;
}

int32_t GetNamePropertyInt32(const napi_env& env, const napi_value& object, const std::string& name)
{
    int32_t value = 0;
    napi_value napiValue = {};
    napi_valuetype tmpType = napi_undefined;
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGD("GetNamePropertyInt32: call napi_typeof fail.");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_LOGD("GetNamePropertyInt32: value is not number");
        return value;
    }
    napi_get_value_int32(env, napiValue, &value);
    MMI_LOGD("GetNamePropertyInt32: %{public}s=%{public}d", name.c_str(), value);
    return value;
}

int64_t GetNamePropertyInt64(const napi_env& env, const napi_value& object, const std::string& name)
{
    int64_t value = 0;
    napi_value napiValue = {};
    napi_valuetype tmpType = napi_undefined;
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGD("GetNamePropertyInt64: call napi_typeof fail.");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_LOGD("GetNamePropertyInt64: value is not number");
        return value;
    }
    napi_get_value_int64(env, napiValue, &value);
    MMI_LOGD("GetNamePropertyInt64: %{public}s=%{public}" PRId64 "", name.c_str(), value);
    return value;
}

uint32_t GetNamePropertyUint32(const napi_env& env, const napi_value& object, const std::string& name)
{
    uint32_t value = 0;
    napi_value napiValue = {};
    napi_valuetype tmpType = napi_undefined;
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_LOGD("GetNamePropertyUint32: call napi_typeof fail.");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_LOGD("GetNamePropertyUint32: value is not number");
        return value;
    }
    napi_get_value_uint32(env, napiValue, &value);
    MMI_LOGD("GetNamePropertyUint32: %{public}s=%{public}d", name.c_str(), value);
    return value;
}
} // namespace MMI
} // namespace OHOS

