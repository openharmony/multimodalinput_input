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

#include "js_input_monitor_module.h"
#include <cinttypes>
#include <string>
#include <uv.h>
#include "define_multimodal.h"
#include "js_input_monitor_manager.h"


namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
        LOG_CORE, MMI_LOG_DOMAIN, "JsInputMonitorModule"
    };
}
static napi_value JsOn(napi_env env, napi_callback_info info)
{
    size_t requireArgc = 2;
    size_t argc;
    napi_value argv[requireArgc];
    napi_status status = napi_generic_failure;

    status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOn get cb info failed");
        return nullptr;
    }
    if (argc < requireArgc) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOn argc is not requireArgc");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;

    status = napi_typeof(env, argv[0], &valueType);
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOn typeof failed");
        return nullptr;
    }
    if (valueType != napi_string) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOn valueType is not napi_string");
        return nullptr;
    }
    char typeName[32] = {0};
    size_t len = 0;
    status = napi_get_value_string_utf8(env, argv[0], typeName, NAPI_AUTO_LENGTH, &len);
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOn napi_get_value_string_utf8 failed");
        return nullptr;
    }
    if (std::strcmp(typeName, "touch") != 0) {
        return nullptr;
    }
    status = napi_typeof(env, argv[1], &valueType);
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOn typeof failed");
        return nullptr;
    }
    if (valueType != napi_function) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOn is not napi_function");
        return nullptr;
    }

    JSIMM.AddMonitor(env, argv[1]);
    return nullptr;
}

static napi_value JsOff(napi_env env, napi_callback_info info)
{
    size_t requireArgc = 1;
    size_t argc;
    napi_value argv[requireArgc];
    napi_status status = napi_generic_failure;

    status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOff get cb info failed");
        return nullptr;
    }
    if (argc < requireArgc) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOff argc is not requireArgc");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;

    status = napi_typeof(env, argv[0], &valueType);
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:GetDeviceIds typeof failed");
        return nullptr;
    }
    if (valueType != napi_string) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:valueType is not napi_string");
        return nullptr;
    }
    char typeName[32] = {0};
    size_t len = 0;
    status = napi_get_value_string_utf8(env, argv[0], typeName, NAPI_AUTO_LENGTH, &len);
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOff napi_get_value_string_utf8 failed");
        return nullptr;
    }
    if (std::strcmp(typeName, "touch") != 0) {
        MMI_LOGE("type error");
        return nullptr;
    }
    status = napi_typeof(env, argv[1], &valueType);
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "MMI Throw Error:JsOff typeof failed");
        return nullptr;
    }
    if (valueType != napi_function) {
        JSIMM.RemoveMonitor(env);
        MMI_LOGD("remove all monitor");
        return nullptr;
    }

    JSIMM.RemoveMonitor(env, argv[1]);
    return nullptr;
}

EXTERN_C_START
static napi_value MmiInputMonitorInit(napi_env env, napi_value exports)
{
    MMI_LOGD("enter");
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", JsOn),
        DECLARE_NAPI_FUNCTION("off", JsOff),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    MMI_LOGD("success");
    return exports;
}
EXTERN_C_END
static napi_module mmiInputMonitorModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = MmiInputMonitorInit,
    .nm_modname = "inputMonitor",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&mmiInputMonitorModule);
}
}
}