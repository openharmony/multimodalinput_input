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

#include "js_input_monitor_module.h"

#include <cinttypes>
#include <string>
#include <uv.h>

#include "define_multimodal.h"
#include "napi_constants.h"
#include "js_input_monitor_manager.h"
#include "proto.h"
#include "util_napi_error.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputMonitorModule" };
constexpr int32_t INVALID_VALUE = -1;
} // namespace

static napi_value JsOnOld(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];

    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc != 2) {
        THROWERR(env, "Register js monitor failed, the number of parameter is error");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    CHKRP(env, napi_typeof(env, argv[0], &valueType), TYPEOF);
    if (valueType != napi_string) {
        THROWERR(env, "Register js monitor failed, value type is not napi_string");
        return nullptr;
    }
    char typeName[MAX_STRING_LEN] = {0};
    size_t len = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[0], typeName, MAX_STRING_LEN - 1, &len), GET_STRING_UTF8);
    if (std::strcmp(typeName, "touch") != 0 && std::strcmp(typeName, "mouse") != 0) {
        THROWERR(env, "Register js monitor failed, the first parameter is invalid");
        return nullptr;
    }

    CHKRP(env, napi_typeof(env, argv[1], &valueType), TYPEOF);
    if (valueType != napi_function) {
        THROWERR(env, "The second param is not napi_function");
        return nullptr;
    }
    if (!JsInputMonMgr.AddEnv(env, info)) {
        THROWERR(env, "AddEnv failed");
        return nullptr;
    }

    JsInputMonMgr.AddMonitor(env, typeName, argv[1]);
    return nullptr;
}

static napi_value JsOnApi9(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];

    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        MMI_HILOGE("Requires 2 Parameters");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "EventType", "int");
        return nullptr;
    }
    if (argc == 1) {
        MMI_HILOGE("First Parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "TouchEventReceiver", "function");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    CHKRP(env, napi_typeof(env, argv[0], &valueType), TYPEOF);
    if (valueType != napi_number) {
        MMI_HILOGE("First Parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "EventType", "int");
        return nullptr;
    }

    int32_t value = INVALID_VALUE;
    CHKRP(env, napi_get_value_int32(env, argv[0], &value), GET_INT32);
    if (value != TOUCH && value != MOUSE) {
        MMI_HILOGE("Into the parameter error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Into the parameter error");
        return nullptr;
    }

    CHKRP(env, napi_typeof(env, argv[1], &valueType), TYPEOF);
    if (valueType != napi_function) {
        MMI_HILOGE("Second Parameter type error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Second Parameter type error");
        return nullptr;
    }

    if (!JsInputMonMgr.AddEnv(env, info)) {
        MMI_HILOGE("AddEnv failed");
        return nullptr;
    }

    std::string typeName;
    if (value == TOUCH) {
        typeName = "touch";
    } else if (value == MOUSE) {
        typeName = "mouse";
    } else {
        MMI_HILOGE("Into the parameter error");
        return nullptr;
    }

    JsInputMonMgr.AddMonitor(env, typeName, argv[1]);
    return nullptr;
}

static napi_value JsOn(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];

    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        THROWERR(env, "Register js monitor failed, the number of parameter is error");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    CHKRP(env, napi_typeof(env, argv[0], &valueType), TYPEOF);
    switch (valueType) {
        case napi_string: {
            JsOnOld(env, info);
            break;
        }
        case napi_number: {
            JsOnApi9(env, info);
            break;
        }
        default: {
            THROWERR(env, "Failed to register JS monitor, value type mismatch");
            return nullptr;
        }
    }
    return nullptr;
}

static napi_value JsOffOld(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[argc];
    argv[0] = nullptr;
    argv[1] = nullptr;

    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > 2) {
        THROWERR(env, "Unregister js monitor failed, the number of parameter is error");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    CHKRP(env, napi_typeof(env, argv[0], &valueType), TYPEOF);
    if (valueType != napi_string) {
        THROWERR(env, "Unregister js monitor failed, value type is not napi_string");
        return nullptr;
    }
    char typeName[MAX_STRING_LEN] = {0};
    size_t len = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[0], typeName, MAX_STRING_LEN - 1, &len), GET_STRING_UTF8);
    if (std::strcmp(typeName, "touch") != 0 && std::strcmp(typeName, "mouse") != 0) {
        THROWERR(env, "Unregister js monitor failed, The first parameter is invalid");
        return nullptr;
    }

    if (argv[1] == nullptr) {
        JsInputMonMgr.RemoveMonitor(env, typeName);
        MMI_HILOGD("Remove all monitor");
        return nullptr;
    }

    CHKRP(env, napi_typeof(env, argv[1], &valueType), TYPEOF);
    if (valueType != napi_function) {
        THROWERR(env, "Unregister js monitor failed, the second param is not napi_function");
        return nullptr;
    }

    if (!JsInputMonMgr.AddEnv(env, info)) {
        JsInputMonMgr.RemoveMonitor(env, typeName);
        THROWERR(env, "Unregister js monitor failed, remove all monitor");
        return nullptr;
    }

    JsInputMonMgr.RemoveMonitor(env, typeName, argv[1]);
    return nullptr;
}

static napi_value JsOffApi9(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[argc];
    argv[0] = nullptr;
    argv[1] = nullptr;

    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        MMI_HILOGE("Requires 2 Parameters");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "EventType", "int");
        return nullptr;
    }
    if (argc == 1) {
        MMI_HILOGE("First Parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "TouchEventReceiver", "function");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    CHKRP(env, napi_typeof(env, argv[0], &valueType), TYPEOF);
    if (valueType != napi_number) {
        MMI_HILOGE("First Parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "EventType", "int");
        return nullptr;
    }

    int32_t value = INVALID_VALUE;
    CHKRP(env, napi_get_value_int32(env, argv[0], &value), GET_INT32);
    if (value != TOUCH && value != MOUSE) {
        MMI_HILOGE("Into the parameter error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Into the parameter error");
        return nullptr;
    }

    std::string typeName;
    if (value == TOUCH) {
        typeName = "touch";
    } else if (value == MOUSE) {
        typeName = "mouse";
    } else {
        MMI_HILOGE("Into the parameter error");
        return nullptr;
    }

    if (argv[1] == nullptr) {
        JsInputMonMgr.RemoveMonitor(env, typeName);
        MMI_HILOGD("Remove all monitor");
        return nullptr;
    }

    CHKRP(env, napi_typeof(env, argv[1], &valueType), TYPEOF);
    if (valueType != napi_function) {
        MMI_HILOGE("Second Parameter type error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Second Parameter type error");
        return nullptr;
    }

    if (!JsInputMonMgr.AddEnv(env, info)) {
        JsInputMonMgr.RemoveMonitor(env, typeName);
        return nullptr;
    }

    JsInputMonMgr.RemoveMonitor(env, typeName, argv[1]);
    return nullptr;
}

static napi_value JsOff(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[argc];
    argv[0] = nullptr;
    argv[1] = nullptr;

    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        THROWERR(env, "Register js monitor failed, the number of parameter is error");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    CHKRP(env, napi_typeof(env, argv[0], &valueType), TYPEOF);
    switch (valueType) {
        case napi_string: {
            JsOffOld(env, info);
            break;
        }
        case napi_number: {
            JsOffApi9(env, info);
            break;
        }
        default: {
            THROWERR(env, "Failed to register JS monitor, value type mismatch");
            return nullptr;
        }
    }
    return nullptr;
}

EXTERN_C_START
napi_value EnumConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = {0};
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = {0};
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value CreateEnumEventType(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value touch = nullptr;
    CHKRP(env, napi_create_int32(env, EventType::TOUCH, &touch), CREATE_INT32);
    napi_value mouse = nullptr;
    CHKRP(env, napi_create_int32(env, EventType::MOUSE, &mouse), CREATE_INT32);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("TOUCH", touch),
        DECLARE_NAPI_STATIC_PROPERTY("MOUSE", mouse),
    };
    napi_value result = nullptr;
    CHKRP(env, napi_define_class(env, "EventType", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(env, napi_set_named_property(env, exports, "EventType", result), SET_NAMED_PROPERTY);
    return exports;
}

static napi_value MmiInputMonitorInit(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", JsOn),
        DECLARE_NAPI_FUNCTION("off", JsOff),
    };
    CHKRP(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc), DEFINE_PROPERTIES);
    if (CreateEnumEventType(env, exports) == nullptr) {
        THROWERR(env, "Failed to create event type enum");
        return nullptr;
    }
    return exports;
}
EXTERN_C_END
static napi_module mmiInputMonitorModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = MmiInputMonitorInit,
    .nm_modname = "multimodalInput.inputMonitor",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&mmiInputMonitorModule);
}
} // namespace MMI
} // namespace OHOS
