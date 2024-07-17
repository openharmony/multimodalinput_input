/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "util_napi_value.h"

#include "key_event_napi.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "UtilNapiValue"

namespace OHOS {
namespace MMI {
napi_status SetNameProperty(const napi_env &env, napi_value &object, const std::string &name, bool value)
{
    napi_value napiValue{};
    auto status = napi_get_boolean(env, value, &napiValue);
    CHKRR(status, "create bool", status);
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    CHKRR(status, "set property", status);
    return status;
}

napi_status SetNameProperty(const napi_env &env, napi_value &object, const std::string &name, uint16_t value)
{
    napi_value napiValue{};
    auto status = napi_create_uint32(env, value, &napiValue);
    CHKRR(status, "create bool", status);
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    CHKRR(status, "set property", status);
    return status;
}

napi_status SetNameProperty(const napi_env &env, napi_value &object, const std::string &name, uint32_t value)
{
    napi_value napiValue{};
    auto status = napi_create_uint32(env, value, &napiValue);
    CHKRR(status, "create uint32", status);
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    CHKRR(status, "set property", status);
    return status;
}

napi_status SetNameProperty(const napi_env &env, napi_value &object, const std::string &name, int32_t value)
{
    napi_value napiValue{};
    auto status = napi_create_int32(env, value, &napiValue);
    CHKRR(status, "create int32", status);
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    CHKRR(status, "set property", status);
    return status;
}

napi_status SetNameProperty(const napi_env &env, napi_value &object, const std::string &name, float value)
{
    napi_value napiValue{};
    auto status = napi_create_double(env, value, &napiValue);
    CHKRR(status, "create uint32", status);
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    CHKRR(status, "set property", status);
    return status;
}

napi_status SetNameProperty(const napi_env &env, napi_value &object, const std::string &name, double value)
{
    napi_value napiValue{};
    auto status = napi_create_double(env, value, &napiValue);
    CHKRR(status, "create double", status);
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    CHKRR(status, "set property", status);
    return status;
}

napi_status SetNameProperty(const napi_env &env, napi_value &object, const std::string &name, int64_t value)
{
    napi_value napiValue{};
    auto status = napi_create_int64(env, value, &napiValue);
    CHKRR(status, "create int64", status);
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    CHKRR(status, "set property", status);
    return status;
}

napi_status SetNameProperty(const napi_env &env, napi_value &object, const std::string &name, std::string value)
{
    napi_value napiValue{};
    auto status = napi_create_string_utf8(env, value.c_str(), NAPI_AUTO_LENGTH, &napiValue);
    CHKRR(status, "create utf8", status);
    status = napi_set_named_property(env, object, name.c_str(), napiValue);
    CHKRR(status, "set property", status);
    return status;
}

napi_status SetNameProperty(
    const napi_env &env, napi_value &object, const std::string &name, std::optional<KeyEvent::KeyItem> &value)
{
    napi_value napiObject{};
    auto status = napi_create_object(env, &napiObject);
    CHECK_RETURN((status == napi_ok) && (napiObject != nullptr), "create object", status);

    status = KeyEventNapi::CreateKeyItem(env, value, napiObject);
    CHKRR(status, "create key property", status);
    status = napi_set_named_property(env, object, name.c_str(), napiObject);
    CHKRR(status, "set key property", status);
    return napi_ok;
}

napi_status SetNameProperty(
    const napi_env &env, napi_value &object, const std::string &name, std::vector<KeyEvent::KeyItem> &value)
{
    napi_value napikeyItems{};
    auto status = napi_create_array(env, &napikeyItems);
    CHKRR(status, "create array", status);
    uint32_t idx = 0;
    for (auto &keyItem : value) {
        napi_value napiKeyItem{};
        status = napi_create_object(env, &napiKeyItem);
        CHECK_RETURN((status == napi_ok) && (napiKeyItem != nullptr), "create object", status);

        std::optional<KeyEvent::KeyItem> opt = std::make_optional(keyItem);
        status = KeyEventNapi::CreateKeyItem(env, opt, napiKeyItem);
        CHKRR(status, "create key property", status);

        status = napi_set_element(env, napikeyItems, idx, napiKeyItem);
        CHKRR(status, "set element", status);
        ++idx;
    }
    status = napi_set_named_property(env, object, "keys", napikeyItems);
    CHKRR(status, "set keys property", status);
    return napi_ok;
}

napi_status SetNameProperty(const napi_env &env, napi_value &object, const std::string &name, napi_value value)
{
    auto status = napi_set_named_property(env, object, name.c_str(), value);
    return status;
}

bool GetNamePropertyBool(const napi_env &env, const napi_value &object, const std::string &name)
{
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        return false;
    }
    bool value = false;
    if (tmpType != napi_boolean) {
        MMI_HILOGI("The value is not bool");
        return value;
    }

    napi_get_value_bool(env, napiValue, &value);
    return value;
}

std::string GetNamePropertyString(const napi_env &env, const napi_value &object, const std::string &name)
{
    std::string value = "";
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        return value;
    }
    if (tmpType != napi_string) {
        MMI_HILOGI("The value is not string");
        return value;
    }

    char tmpValue[MAX_STRING_LEN] = { 0 };
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, napiValue, tmpValue, MAX_STRING_LEN - 1, &typeLen);
    value = tmpValue;
    return value;
}

int32_t GetNamePropertyInt32(const napi_env &env, const napi_value &object, const std::string &name)
{
    int32_t value = 0;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_HILOGI("The value is not number");
        return value;
    }
    napi_get_value_int32(env, napiValue, &value);
    return value;
}

int64_t GetNamePropertyInt64(const napi_env &env, const napi_value &object, const std::string &name)
{
    int64_t value = 0;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_HILOGI("The value is not number");
        return value;
    }
    napi_get_value_int64(env, napiValue, &value);
    return value;
}

uint32_t GetNamePropertyUint32(const napi_env &env, const napi_value &object, const std::string &name)
{
    uint32_t value = 0;
    napi_value napiValue = {};
    napi_get_named_property(env, object, name.c_str(), &napiValue);
    napi_valuetype tmpType = napi_undefined;
    if (napi_typeof(env, napiValue, &tmpType) != napi_ok) {
        MMI_HILOGE("Call napi_typeof failed");
        return value;
    }
    if (tmpType != napi_number) {
        MMI_HILOGI("The value is not number");
        return value;
    }
    napi_get_value_uint32(env, napiValue, &value);
    return value;
}

KeyEvent::KeyItem GetNamePropertyKeyItem(const napi_env &env, const napi_value &object, const std::string &name)
{
    napi_value napiValue{};
    auto status = napi_get_named_property(env, object, name.c_str(), &napiValue);
    CHKRR(status, "get KeyItem property failed", {});
    KeyEvent::KeyItem keyItem;
    int32_t keyCode = GetNamePropertyInt32(env, napiValue, "code");
    keyItem.SetKeyCode(keyCode);
    int64_t pressedTime = GetNamePropertyInt64(env, napiValue, "pressedTime");
    keyItem.SetDownTime(pressedTime);
    int32_t deviceId = GetNamePropertyInt32(env, napiValue, "deviceId");
    keyItem.SetDeviceId(deviceId);
    return keyItem;
}

std::vector<KeyEvent::KeyItem> GetNamePropertyKeyItems(
    const napi_env &env, const napi_value &object, const std::string &name)
{
    napi_value napiValue = {};
    auto status = napi_get_named_property(env, object, name.c_str(), &napiValue);
    CHKRR(status, "get property", {});

    uint32_t length = 0;
    status = napi_get_array_length(env, napiValue, &length);
    CHKRR(status, "get array length", {});

    std::vector<KeyEvent::KeyItem> keyItems;
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element = {};
        status = napi_get_element(env, napiValue, i, &element);
        CHECK_RETURN((status == napi_ok) && (element != nullptr), "get element", {});
        KeyEvent::KeyItem keyItem;
        status = KeyEventNapi::GetKeyItem(env, element, keyItem);
        CHKRR(status, "read keyItem property", {});
        keyItems.push_back(keyItem);
    }
    return keyItems;
}
} // namespace MMI
} // namespace OHOS