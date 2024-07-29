/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "js_input_monitor_module.h"

#include <cinttypes>
#include <string>
#include <uv.h>

#include "define_multimodal.h"
#include "js_input_monitor_manager.h"
#include "napi_constants.h"
#include "proto.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsInputMonitorModule"

namespace OHOS {
namespace MMI {
namespace {
const std::set<std::string> ACTION_TYPE = {
    "touch", "mouse", "pinch", "threeFingersSwipe", "fourFingersSwipe", "rotate", "threeFingersTap", "joystick",
    "fingerprint", "swipeInward"
};
constexpr int32_t TWO_PARAMETERS { 2 };
constexpr int32_t THREE_PARAMETERS { 3 };
constexpr int32_t RECT_LIST_SIZE { 2 };
} // namespace

static napi_value JsOnApi9(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };

    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    napi_valuetype valueType = napi_undefined;
    CHKRP(napi_typeof(env, argv[0], &valueType), TYPEOF);
    if (valueType != napi_string) {
        MMI_HILOGE("First Parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "EventType", "string");
        return nullptr;
    }
    char typeName[MAX_STRING_LEN] = { 0 };
    size_t len = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], typeName, MAX_STRING_LEN - 1, &len), GET_VALUE_STRING_UTF8);
    if (ACTION_TYPE.find(typeName) == ACTION_TYPE.end()) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "EventType is invalid");
        return nullptr;
    }
    CHKRP(napi_typeof(env, argv[1], &valueType), TYPEOF);
    if (valueType != napi_function) {
        MMI_HILOGE("Second Parameter type error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Second Parameter type error");
        return nullptr;
    }
    if (!JS_INPUT_MONITOR_MGR.AddEnv(env, info)) {
        MMI_HILOGE("AddEnv failed");
        return nullptr;
    }
    JS_INPUT_MONITOR_MGR.AddMonitor(env, typeName, argv[1]);
    return nullptr;
}

static void AddMouseMonitor(napi_env env, napi_callback_info info, napi_value napiRect, napi_value napiCallback)
{
    std::vector<Rect> hotRectAreaList;
    uint32_t rectArrayLength = 0;
    CHKRV(napi_get_array_length(env, napiRect, &rectArrayLength), GET_ARRAY_LENGTH);
    if (rectArrayLength <= 0 || rectArrayLength > RECT_LIST_SIZE) {
        MMI_HILOGE("Hot Rect Area Parameter error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Hot Rect Area Parameter error");
        return;
    }
    hotRectAreaList = JS_INPUT_MONITOR_MGR.GetHotRectAreaList(env, napiRect, rectArrayLength);
    if (hotRectAreaList.size() != rectArrayLength) {
        MMI_HILOGE("Hot Rect Area Parameter error");
        return;
    }
    napi_valuetype valueType = napi_undefined;
    CHKRV(napi_typeof(env, napiCallback, &valueType), TYPEOF);
    if (valueType != napi_function) {
        MMI_HILOGE("Third Parameter type error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Third Parameter type error");
        return;
    }
    if (!JS_INPUT_MONITOR_MGR.AddEnv(env, info)) {
        MMI_HILOGE("AddEnv failed");
        return;
    }
    JS_INPUT_MONITOR_MGR.AddMonitor(env, "mouse", hotRectAreaList, rectArrayLength, napiCallback);
    return;
}

static napi_value AddMonitor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    napi_valuetype valueType = napi_undefined;
    CHKRP(napi_typeof(env, argv[0], &valueType), TYPEOF);
    if (valueType != napi_string) {
        MMI_HILOGE("First Parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "EventType", "string");
        return nullptr;
    }
    char typeName[MAX_STRING_LEN] = { 0 };
    size_t len = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], typeName, MAX_STRING_LEN - 1, &len), GET_VALUE_STRING_UTF8);
    if (ACTION_TYPE.find(typeName) == ACTION_TYPE.end()) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "EventType is invalid");
        return nullptr;
    }
    if (strcmp(typeName, "mouse") == 0) {
        AddMouseMonitor(env, info, argv[1], argv[TWO_PARAMETERS]);
    } else {
        CHKRP(napi_typeof(env, argv[1], &valueType), TYPEOF);
        if (valueType != napi_number) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Second Parameter type error");
            return nullptr;
        }
        int32_t fingers = 0;
        CHKRP(napi_get_value_int32(env, argv[1], &fingers), GET_VALUE_INT32);
        if (fingers < 0) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "fingers is invalid");
            return nullptr;
        }

        CHKRP(napi_typeof(env, argv[TWO_PARAMETERS], &valueType), TYPEOF);
        if (valueType != napi_function) {
            THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Third Parameter type error");
            return nullptr;
        }
        if (!JS_INPUT_MONITOR_MGR.AddEnv(env, info)) {
            MMI_HILOGE("AddEnv failed");
            return nullptr;
        }
        JS_INPUT_MONITOR_MGR.AddMonitor(env, typeName, argv[TWO_PARAMETERS], fingers);
    }
    return nullptr;
}

static napi_value JsOn(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < TWO_PARAMETERS) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "parameter number error");
        return nullptr;
    }
    if (argc == TWO_PARAMETERS) {
        JsOnApi9(env, info);
    } else if (argc == THREE_PARAMETERS) {
        AddMonitor(env, info);
    }
    return nullptr;
}

static napi_value JsOffApi9(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    napi_valuetype valueType = napi_undefined;
    CHKRP(napi_typeof(env, argv[0], &valueType), TYPEOF);
    if (valueType != napi_string) {
        MMI_HILOGE("First Parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "EventType", "string");
        return nullptr;
    }
    char typeName[MAX_STRING_LEN] = { 0 };
    size_t len = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], typeName, MAX_STRING_LEN - 1, &len), GET_VALUE_STRING_UTF8);
    if (ACTION_TYPE.find(typeName) == ACTION_TYPE.end()) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "EventType is invalid");
        return nullptr;
    }
    if (argc < TWO_PARAMETERS) {
        JS_INPUT_MONITOR_MGR.RemoveMonitor(env, typeName);
        MMI_HILOGD("Remove all monitor");
        return nullptr;
    }

    CHKRP(napi_typeof(env, argv[1], &valueType), TYPEOF);
    if (valueType != napi_function) {
        MMI_HILOGE("Second Parameter type error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Second Parameter type error");
        return nullptr;
    }

    if (!JS_INPUT_MONITOR_MGR.AddEnv(env, info)) {
        JS_INPUT_MONITOR_MGR.RemoveMonitor(env, typeName);
        return nullptr;
    }

    JS_INPUT_MONITOR_MGR.RemoveMonitor(env, typeName, argv[1]);
    return nullptr;
}

static napi_value RemoveMonitor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    napi_valuetype valueType = napi_undefined;
    CHKRP(napi_typeof(env, argv[0], &valueType), TYPEOF);
    if (valueType != napi_string) {
        MMI_HILOGE("First Parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "EventType", "string");
        return nullptr;
    }
    char typeName[MAX_STRING_LEN] = { 0 };
    size_t len = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], typeName, MAX_STRING_LEN - 1, &len), GET_VALUE_STRING_UTF8);
    if (ACTION_TYPE.find(typeName) == ACTION_TYPE.end()) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "EventType is invalid");
        return nullptr;
    }
    CHKRP(napi_typeof(env, argv[1], &valueType), TYPEOF);
    if (valueType != napi_number) {
        MMI_HILOGE("Second Parameter type error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Second Parameter type error");
        return nullptr;
    }
    int32_t fingers = 0;
    CHKRP(napi_get_value_int32(env, argv[1], &fingers), GET_VALUE_INT32);
    if (fingers < 0) {
        MMI_HILOGE("Invalid fingers");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "fingers is invalid");
        return nullptr;
    }
    if (argc < THREE_PARAMETERS) {
        JS_INPUT_MONITOR_MGR.RemoveMonitor(env, typeName, fingers);
        MMI_HILOGD("Remove all monitor");
        return nullptr;
    }
    CHKRP(napi_typeof(env, argv[TWO_PARAMETERS], &valueType), TYPEOF);
    if (valueType != napi_function) {
        MMI_HILOGE("Second Parameter type error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Second Parameter type error");
        return nullptr;
    }
    if (!JS_INPUT_MONITOR_MGR.AddEnv(env, info)) {
        JS_INPUT_MONITOR_MGR.RemoveMonitor(env, typeName, fingers);
        return nullptr;
    }

    JS_INPUT_MONITOR_MGR.RemoveMonitor(env, typeName, argv[TWO_PARAMETERS], fingers);
    return nullptr;
}

static napi_value JsOff(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };

    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "parameter number error");
        return nullptr;
    }
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[1], &valueType);

    if (argc == 1 || napi_function == valueType) {
        JsOffApi9(env, info);
    } else {
        RemoveMonitor(env, info);
    }
    return nullptr;
}

EXTERN_C_START
static napi_value MmiInputMonitorInit(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", JsOn),
        DECLARE_NAPI_FUNCTION("off", JsOff),
    };
    CHKRP(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc), DEFINE_PROPERTIES);
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
