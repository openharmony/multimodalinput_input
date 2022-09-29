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

#include <cinttypes>

#include "napi_constants.h"
#include "util_napi.h"
#include "util_napi_error.h"
#include "js_register_module.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterUtil" };
} // namespace
int32_t GetNamedPropertyBool(const napi_env& env, const napi_value& object, const std::string& name, bool& ret)
{
    napi_value napiValue = {};
    CHKRF(env, napi_get_named_property(env, object, name.c_str(), &napiValue), GET_NAMED_PROPERTY);
    if (napiValue == nullptr) {
        MMI_HILOGE("The value is null");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Invalid KeyEvent");
        return RET_ERR;
    }
    napi_valuetype tmpType = napi_undefined;
    CHKRF(env, napi_typeof(env, napiValue, &tmpType), TYPEOF);
    if (tmpType != napi_boolean) {
        MMI_HILOGE("The name is not bool");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, name.c_str(), "bool");
        return RET_ERR;
    }
    CHKRF(env, napi_get_value_bool(env, napiValue, &ret), GET_BOOL);
    return RET_OK;
}

int32_t GetNamedPropertyInt32(const napi_env& env, const napi_value& object, const std::string& name, int32_t& ret)
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
        MMI_HILOGE("The value is not int32_t");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, name.c_str(), "int");
        return RET_ERR;
    }
    if (napi_get_value_int32(env, napiValue, &ret) != napi_ok) {
        MMI_HILOGE("NapiElement get int32 value failed");
        return RET_ERR;
    }
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
