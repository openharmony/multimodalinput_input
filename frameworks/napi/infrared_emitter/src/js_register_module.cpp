/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <linux/input.h>

#include "input_manager.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi_error.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsInfraredRegister"

namespace OHOS {
namespace MMI {
namespace {
const uint32_t NUMBER_PARAMETERS = 2;
const int32_t  MAX_NUMBER_ARRAY_ELEMENT = 50;
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
    napi_status ret = napi_is_array(env, value, &isArray);
    if (ret != napi_ok) {
        return false;
    }
    return isArray;
}

bool ParseInt64(const napi_env& env, const napi_value& value, int64_t& result)
{
    if (!CheckType(env, value, napi_number)) {
        MMI_HILOGE("ParseInt64 type not number");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "element of pattern", "Number");
        return false;
    }
    if (napi_get_value_int64(env, value, &result) != napi_ok) {
        MMI_HILOGE("ParseInt64 cannot get value int64");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "element of pattern", "Int64");
        return false;
    }
    return true;
}

bool ParsePatternArray(const napi_env& env, const napi_value& value, std::vector<int64_t>& result)
{
    uint32_t length = 0;
    if (!IsArray(env, value)) {
        MMI_HILOGE("ParsePatternArray second para not array");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "pattern", "Array");
        return false;
    }
    napi_get_array_length(env, value, &length);
    for (uint32_t i = 0; i < length; i++) {
        napi_value valueArray = nullptr;
        if (napi_get_element(env, value, i, &valueArray) != napi_ok) {
            MMI_HILOGE("ParsePatternArray napi_get_element failed. index:%{public}d", i);
            return false;
        }
        int64_t res = 0;
        if (!ParseInt64(env, valueArray, res)) {
            MMI_HILOGE("ParsePatternArray parse array fail. index:%{public}d", i);
            THROWERR_API9(env, COMMON_PARAMETER_ERROR, "element of pattern", "Int64");
            return false;
        }
        if (res <= 0) {
            THROWERR_API9(env, COMMON_PARAMETER_ERROR, "value for element of pattern", "must be positive");
            return false;
        }
        result.emplace_back(res);
    }
    return true;
};

bool ParseTransmitInfraredJSParam(const napi_env& env, const napi_callback_info &info, int64_t & infraredFrequency,
                                  std::vector<int64_t> & vecPattern)
{
    CALL_DEBUG_ENTER;
    size_t argc = NUMBER_PARAMETERS;
    napi_value argv[NUMBER_PARAMETERS];
    CHKRF(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc != NUMBER_PARAMETERS) {
        MMI_HILOGE("ParseTransmitInfraredJSParam Parameter number error");
        return false;
    }
    if (!CheckType(env, argv[0], napi_number)) {
        MMI_HILOGE("ParseTransmitInfraredJSParam infraredFrequency parameter[0] type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "infraredFrequency", "number");
        return false;
    }
    CHKRF(napi_get_value_int64(env, argv[0], &infraredFrequency), "get number64 value error");
    if (infraredFrequency <= 0) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "value of infraredFrequency", "must be greater than 0");
        return false;
    }
    if (!ParsePatternArray(env, argv[1], vecPattern)) {
        MMI_HILOGE("ParsePatternArray parse pattern array fail");
        return false;
    }
    if (vecPattern.size() > MAX_NUMBER_ARRAY_ELEMENT) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "size of pattern", "must be less than or equal  50");
        return false;
    }
    return true;
}

static void ThrowError(napi_env env, int32_t code, std::string operateType)
{
    int32_t errorCode = -code;
    if (code > 0) {
        errorCode = code;
    }
    MMI_HILOGE("Operate %{public}s requst error. returnCode:%{public}d", operateType.c_str(), code);
    if (errorCode == COMMON_PERMISSION_CHECK_ERROR) {
        THROWERR_API9(env, COMMON_PERMISSION_CHECK_ERROR, "Infrared", "ohos.permission.MANAGE_INPUT_INFRARED_EMITTER");
    } else if (COMMON_USE_SYSAPI_ERROR == errorCode) {
        THROWERR_API9(env, COMMON_USE_SYSAPI_ERROR, "Infrared", "Non system applications use system API");
    } else {
        return;
    }
}

napi_value CreateInfraredFrequencyItem(napi_env env, const InfraredFrequency &infraredFrequency)
{
    napi_value result;
    napi_status status = napi_create_object(env, &result);
    CHKRP(status, CREATE_OBJECT);
    napi_value jsMax;
    CHKRP(napi_create_int64(env, infraredFrequency.max_, &jsMax), "napi_create_int64:max");
    CHKRP(napi_set_named_property(env, result, "max", jsMax), SET_NAMED_PROPERTY);
    napi_value jsMin;
    CHKRP(napi_create_int64(env, infraredFrequency.min_, &jsMin), "napi_create_int64:min");
    CHKRP(napi_set_named_property(env, result, "min", jsMin), SET_NAMED_PROPERTY);
    return result;
}

static napi_value HasIrEmitter(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    napi_status status = napi_get_boolean(env, true, &result);
    if (status != napi_ok) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "type", "boolean");
        return nullptr;
    }
    return result;
}

static napi_value GetInfraredFrequencies(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    CHKRP(napi_create_array(env, &result), CREATE_ARRAY);
    std::vector<InfraredFrequency> requencys;
    int32_t ret = InputManager::GetInstance()->GetInfraredFrequencies(requencys);
    if (ret != RET_OK) {
        if (RET_OK > ret || COMMON_PERMISSION_CHECK_ERROR == ret || ERROR_NOT_SYSAPI == ret) {
            MMI_HILOGE("js_register.GetFreq reqErr. Permi Err or Not System APP. Positive retCode:%{public}d", ret);
            ThrowError(env, ret, "GetInfraredFrequencies");
        }
        MMI_HILOGE("Parse GetInfraredFrequencies requst error. returnCode:%{public}d", ret);
        return result;
    }
    size_t size = requencys.size();
    std::string logPrint = "size:" + std::to_string(size) + ";";
    CHKRP(napi_create_array(env, &result), CREATE_ARRAY);
    for (size_t i = 0; i < size; i++) {
        InfraredFrequency frequencyItem = requencys[i];
        logPrint = logPrint + std::to_string(i) + "max:" + std::to_string(frequencyItem.max_) + ";min:"
                    + std::to_string(frequencyItem.min_) + ";";
        napi_value item = CreateInfraredFrequencyItem(env, requencys[i]);
        if (item == nullptr) {
            MMI_HILOGE("CreateInfraredFrequencyItem error");
            return nullptr;
        }
        CHKRP(napi_set_element(env, result, i, item), SET_ELEMENT);
    }
    MMI_HILOGD("js_register_module.GetInfraredFrequencies :%{public}s ", logPrint.c_str());
    return result;
}

static napi_value TransmitInfrared(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value result = nullptr;
    int64_t number = -1;
    std::vector<int64_t> pattern;
    if (!ParseTransmitInfraredJSParam(env, info, number, pattern)) {
        MMI_HILOGE("Parse TransmitInfrared JSParam error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parse TransmitInfrared JSParam error");
        return nullptr;
    }
    int32_t size = static_cast<int32_t>(pattern.size());
    std::string context = "number:" + std::to_string(number) + "\n;" + "; size=" + std::to_string(size) + ";";
    for (int32_t i = 0; i < size; i++) {
        context = context + std::to_string(i) + ": pattern: " + std::to_string(pattern[i]) + ";";
    }
    MMI_HILOGD("js_register_module.TransmitInfrared para size :%{public}s", context.c_str());
    int32_t ret = InputManager::GetInstance()->TransmitInfrared(number, pattern);
    if (ret != RET_OK) {
        if (RET_OK > ret || COMMON_PERMISSION_CHECK_ERROR == ret || ERROR_NOT_SYSAPI == ret) {
            MMI_HILOGE("js_register.Transmit req err. Per Er or Not Sys APP. Posi retCode:%{public}d", ret);
            ThrowError(env, ret, "TransmitInfrared");
        }
        MMI_HILOGE("js_register_module.TransmitInfrared requst error. returnCode:%{public}d", ret);
        return nullptr;
    }
    CHKRP(napi_create_int32(env, 0, &result), CREATE_INT32);
    return result;
}

EXTERN_C_START
static napi_value MmiInit(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("hasIrEmitter", HasIrEmitter),
        DECLARE_NAPI_FUNCTION("getInfraredFrequencies", GetInfraredFrequencies),
        DECLARE_NAPI_FUNCTION("transmitInfrared", TransmitInfrared)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
EXTERN_C_END

static napi_module infraredModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = MmiInit,
    .nm_modname = "multimodalInput.infraredEmitter",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&infraredModule);
}
}
}