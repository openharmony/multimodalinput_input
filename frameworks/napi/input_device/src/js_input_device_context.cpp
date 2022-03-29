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

#include "js_input_device_context.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputDeviceContext" };
} // namespace

JsInputDeviceContext::JsInputDeviceContext()
{
    mager_ = std::make_shared<JsInputDeviceManager>();
    CHKPL(mager_);
}

JsInputDeviceContext::~JsInputDeviceContext()
{
    std::lock_guard<std::mutex> guard(mtx_);
    auto jsInputDeviceMgr =  mager_;
    mager_.reset();
    if (jsInputDeviceMgr) {
        jsInputDeviceMgr->ResetEnv();
    }
}

napi_value JsInputDeviceContext::CreateInstance(napi_env env)
{
    CALL_LOG_ENTER;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), "napi_get_global");

    constexpr char className[] = "JsInputDeviceContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    napi_status status = napi_define_class(env, className, sizeof(className), JsInputDeviceContext::JsConstructor,
                                           nullptr, sizeof(desc) / sizeof(desc[0]), nullptr, &jsClass);
    CHKRP(env, status, "napi_define_class");

    status = napi_set_named_property(env, global, "multimodalinput_input_device_class", jsClass);
    CHKRP(env, status, "napi_set_named_property");

    napi_value jsInstance = nullptr;
    CHKRP(env, napi_new_instance(env, jsClass, 0, nullptr, &jsInstance), "napi_new_instance");
    CHKRP(env, napi_set_named_property(env, global, "multimodal_input_device", jsInstance), "napi_set_named_property");

    JsInputDeviceContext *jsContext = nullptr;
    CHKRP(env, napi_unwrap(env, jsInstance, (void**)&jsContext), "napi_unwrap");
    CHKPP(jsContext);
    CHKRP(env, napi_create_reference(env, jsInstance, 1, &(jsContext->contextRef_)), "napi_create_reference");

    uint32_t refCount = 0;
    CHKRP(env, napi_reference_ref(env, jsContext->contextRef_, &refCount), "napi_reference_ref");
    return jsInstance;
}

napi_value JsInputDeviceContext::JsConstructor(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data), "napi_get_cb_info");

    JsInputDeviceContext *jsContext = new (std::nothrow) JsInputDeviceContext();
    CHKPP(jsContext);
    napi_status status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void* data, void* hin) {
        MMI_HILOGI("jsvm ends");
        JsInputDeviceContext *context = (JsInputDeviceContext*)data;
        delete context;
    }, nullptr, nullptr);
    CHKRP(env, status, "napi_wrap");
    return thisVar;
}

JsInputDeviceContext* JsInputDeviceContext::GetInstance(napi_env env)
{
    CALL_LOG_ENTER;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), "napi_get_global");

    bool result = false;
    napi_has_named_property(env, global, "multimodal_input_device", &result);
    if (!result) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: multimodal_input_device was not found");
        MMI_HILOGE("multimodal_input_device was not found");
        return nullptr;
    }

    napi_value object = nullptr;
    CHKRP(env, napi_get_named_property(env, global, "multimodal_input_device", &object), "napi_get_named_property");
    if (object == nullptr) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: object is nullptr");
        MMI_HILOGE("object is nullptr");
        return nullptr;
    }

    JsInputDeviceContext *instance = nullptr;
    CHKRP(env, napi_unwrap(env, object, (void**)&instance), "napi_unwrap");
    if (instance == nullptr) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: instance is nullptr");
        MMI_HILOGE("instance is nullptr");
        return nullptr;
    }
    return instance;
}

std::shared_ptr<JsInputDeviceManager> JsInputDeviceContext::GetJsInputDeviceMgr() const
{
    return mager_;
}

napi_value JsInputDeviceContext::GetDeviceIds(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), "napi_get_cb_info");
    if (argc > 1) {
        MMI_HILOGE("too many parameters");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: too many parameters");
        return nullptr;
    }

    JsInputDeviceContext *jsIds = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsIds->GetJsInputDeviceMgr();
    if (argc == 0) {
        return jsInputDeviceMgr->GetDeviceIds(env);
    }

    napi_valuetype valueType = napi_undefined;
    CHKRP(env, napi_typeof(env, argv[0], &valueType), "napi_typeof");
    if (valueType != napi_function) {
        MMI_HILOGE("the first parameter is not a function");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the first parameter is not a function");
        return nullptr;
    }
    return jsInputDeviceMgr->GetDeviceIds(env, argv[0]);
}

napi_value JsInputDeviceContext::GetDevice(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), "napi_get_cb_info");
    if (argc < 1 || argc > 2) {
        MMI_HILOGE("the number of parameters is not as expected");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the number of parameters is not as expected");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    CHKRP(env, napi_typeof(env, argv[0], &valueType), "napi_typeof");
    if (valueType != napi_number) {
        MMI_HILOGE("the first parameter is not a number");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the first parameter is not a number");
        return nullptr;
    }
    int32_t id = 0;
    CHKRP(env, napi_get_value_int32(env, argv[0], &id), "napi_get_value_int32");

    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc == 1) {
        MMI_HILOGD("promise end");
        return jsInputDeviceMgr->GetDevice(env, id);
    }
    CHKRP(env, napi_typeof(env, argv[1], &valueType), "napi_typeof");
    if (valueType != napi_function) {
        MMI_HILOGE("the second parameter is not a function");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the second parameter is not a function");
        return nullptr;
    }
    return jsInputDeviceMgr->GetDevice(env, id, argv[1]);
}

napi_value JsInputDeviceContext::GetKeystrokeAbility(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    size_t argc = 7;
    napi_value argv[7];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), "napi_get_cb_info");
    if (argc < 2 || argc > 7) {
        MMI_HILOGE("parameter number error, argc: %{public}zu", argc);
        napi_throw_error(env, nullptr, "JsInputDeviceContext: parameter number error");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    CHKRP(env, napi_typeof(env, argv[0], &valueType), "napi_typeof");
    if (valueType != napi_number) {
        MMI_HILOGE("the first parameter is not a number");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the first parameter is not a number");
        return nullptr;
    }
    int32_t deviceId = 0;
    CHKRP(env, napi_get_value_int32(env, argv[0], &deviceId), "napi_get_value_int32");

    for (size_t i = 0; i < argc; ++i) {
        CHKRP(env, napi_typeof(env, argv[i], &valueType), "napi_typeof");
        if (valueType == napi_undefined) {
            argc = i;
            break;
        }
    }

    int32_t data = 0;
    std::vector<int32_t> keyCodes;
    for (size_t i = 1; i < argc - 1; ++i) {
        CHKRP(env, napi_typeof(env, argv[i], &valueType), "napi_typeof");
        if (valueType != napi_number) {
            MMI_HILOGE("the %{public}zu parameter is not a number", i);
            napi_throw_error(env, nullptr, "JsInputDeviceContext: parameter type error");
            return nullptr;
        }
        CHKRP(env, napi_get_value_int32(env, argv[i], &data), "napi_get_value_int32");
        keyCodes.push_back(data);
    }

    JsInputDeviceContext *jsContext = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsContext->GetJsInputDeviceMgr();
    CHKRP(env, napi_typeof(env, argv[argc - 1], &valueType), "napi_typeof");
    if (valueType == napi_number) {
        CHKRP(env, napi_get_value_int32(env, argv[argc - 1], &data), "napi_get_value_int32");
        keyCodes.push_back(data);
        return jsInputDeviceMgr->GetKeystrokeAbility(env, deviceId, keyCodes);
    }

    CHKRP(env, napi_typeof(env, argv[argc - 1], &valueType), "napi_typeof");
    if (argc == 2 && valueType == napi_function) {
        MMI_HILOGE("the number of parameters is incorrect");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the number of parameters is incorrect");
        return nullptr;
    }
    if (valueType != napi_function) {
        MMI_HILOGE("the last parameter is not a function");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the last parameter is not a function");
        return nullptr;
    }
    return jsInputDeviceMgr->GetKeystrokeAbility(env, deviceId, keyCodes, argv[argc - 1]);
}

napi_value JsInputDeviceContext::Export(napi_env env, napi_value exports)
{
    CALL_LOG_ENTER;
    auto instance = CreateInstance(env);
    if (instance == nullptr) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to create instance");
        MMI_HILOGE("failed to create instance");
        return nullptr;
    }
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getDevice", GetDevice),
        DECLARE_NAPI_STATIC_FUNCTION("getDeviceIds", GetDeviceIds),
        DECLARE_NAPI_STATIC_FUNCTION("getKeystrokeAbility", GetKeystrokeAbility),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
} // namespace MMI
} // namespace OHOS
