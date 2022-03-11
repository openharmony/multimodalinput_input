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
    napi_status status = napi_get_global(env, &global);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to call napi_get_global");
        MMI_LOGE("failed to call napi_get_global");
        return nullptr;
    }

    constexpr char className[] = "JsInputDeviceContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    status = napi_define_class(env, className, sizeof(className), JsInputDeviceContext::JsConstructor, nullptr,
        sizeof(desc) / sizeof(desc[0]), nullptr, &jsClass);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to call napi_define_class");
        MMI_LOGE("failed to call napi_define_class");
        return nullptr;
    }

    status = napi_set_named_property(env, global, "multimodalinput_input_device_class", jsClass);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to set jsClass property");
        MMI_LOGE("failed to set jsClass property");
        return nullptr;
    }

    napi_value jsInstance = nullptr;
    status = napi_new_instance(env, jsClass, 0, nullptr, &jsInstance);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to create jsInstance");
        MMI_LOGE("failed to create jsInstance");
        return nullptr;
    }
    status = napi_set_named_property(env, global, "multimodal_input_device", jsInstance);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to set jsInstance property");
        MMI_LOGE("failed to set jsInstance property");
        return nullptr;
    }

    JsInputDeviceContext *jsContext = nullptr;
    status = napi_unwrap(env, jsInstance, (void**)&jsContext);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to get jsContext");
        MMI_LOGE("failed to get jsContext");
        return nullptr;
    }
    CHKPP(jsContext);
    status = napi_create_reference(env, jsInstance, 1, &(jsContext->contextRef_));
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to create contextRef_");
        MMI_LOGE("failed to create contextRef_");
        return nullptr;
    }

    uint32_t refCount = 0;
    status = napi_reference_ref(env, jsContext->contextRef_, &refCount);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to create contextRef_ reference");
        MMI_LOGE("failed to create contextRef_ reference");
        return nullptr;
    }
    return jsInstance;
}

napi_value JsInputDeviceContext::JsConstructor(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to get thisVar");
        MMI_LOGE("failed to get thisVar");
        return nullptr;
    }

    JsInputDeviceContext *jsContext = new (std::nothrow) JsInputDeviceContext();
    CHKPP(jsContext);
    status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void* data, void* hin) {
        MMI_LOGI("jsvm ends");
        JsInputDeviceContext *context = (JsInputDeviceContext*)data;
        delete context;
    }, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to wrap jsContext");
        MMI_LOGE("failed to wrap jsContext");
        return nullptr;
    }
    return thisVar;
}

JsInputDeviceContext* JsInputDeviceContext::GetInstance(napi_env env)
{
    CALL_LOG_ENTER;
    napi_value global = nullptr;
    napi_status status = napi_get_global(env, &global);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to get global");
        MMI_LOGE("failed to get global");
        return nullptr;
    }

    bool result = false;
    napi_has_named_property(env, global, "multimodal_input_device", &result);
    if (!result) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: multimodal_input_device was not found");
        MMI_LOGE("multimodal_input_device was not found");
        return nullptr;
    }

    napi_value object = nullptr;
    status = napi_get_named_property(env, global, "multimodal_input_device", &object);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to get multimodal_input_device");
        MMI_LOGE("failed to get multimodal_input_device");
        return nullptr;
    }
    if (object == nullptr) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: object is nullptr");
        MMI_LOGE("object is nullptr");
        return nullptr;
    }

    JsInputDeviceContext *instance = nullptr;
    status = napi_unwrap(env, object, (void**)&instance);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to get instance");
        MMI_LOGE("failed to get instance");
        return nullptr;
    }
    if (instance == nullptr) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: instance is nullptr");
        MMI_LOGE("instance is nullptr");
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
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        MMI_LOGE("parameter acquisition failed");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: parameter acquisition failed");
        return nullptr;
    }
    if (argc > 1) {
        MMI_LOGE("too many parameters");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: too many parameters");
        return nullptr;
    }

    JsInputDeviceContext *jsIds = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsIds->GetJsInputDeviceMgr();
    if (argc == 0) {
        return jsInputDeviceMgr->GetDeviceIds(env);
    }

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, argv[0], &valueType);
    if (status != napi_ok) {
        MMI_LOGE("failed to get the first parameter type");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to get the first parameter type");
        return nullptr;
    }
    if (valueType != napi_function) {
        MMI_LOGE("the first parameter is not a function");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the first parameter is not a function");
        return nullptr;
    }
    jsInputDeviceMgr->GetDeviceIds(env, argv[0]);
    return nullptr;
}

napi_value JsInputDeviceContext::GetDevice(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: parameter acquisition failed");
        return nullptr;
    }
    if (argc < 1 || argc > 2) {
        MMI_LOGE("the number of parameters is not as expected");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the number of parameters is not as expected");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    status = napi_typeof(env, argv[0], &valueType);
    if (status != napi_ok) {
        MMI_LOGE("failed to get the first parameter type");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to get the first parameter type");
        return nullptr;
    }
    if (valueType != napi_number) {
        MMI_LOGE("the first parameter is not a number");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the first parameter is not a number");
        return nullptr;
    }
    int32_t id = 0;
    status = napi_get_value_int32(env, argv[0], &id);
    if (status != napi_ok) {
        MMI_LOGE("failed to get id");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to get id");
        return nullptr;
    }

    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc == 1) {
        MMI_LOGD("promise end");
        return jsInputDeviceMgr->GetDevice(id, env);
    }
    status = napi_typeof(env, argv[1], &valueType);
    if (status != napi_ok) {
        MMI_LOGE("failed to get the second parameter type");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to get the second parameter type");
        return nullptr;
    }
    if (valueType != napi_function) {
        MMI_LOGE("the second parameter is not a function");
        napi_throw_error(env, nullptr, "JsInputDeviceContext: the second parameter is not a function");
        return nullptr;
    }
    jsInputDeviceMgr->GetDevice(id, env, argv[1]);
    return nullptr;
}

napi_value JsInputDeviceContext::Export(napi_env env, napi_value exports)
{
    CALL_LOG_ENTER;
    auto instance = CreateInstance(env);
    if (instance == nullptr) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to create instance");
        MMI_LOGE("failed to create instance");
        return nullptr;
    }
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("getDevice", GetDevice),
        DECLARE_NAPI_STATIC_FUNCTION("getDeviceIds", GetDeviceIds),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
} // namespace MMI
} // namespace OHOS
