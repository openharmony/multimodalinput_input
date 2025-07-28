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

#include "js_short_key_context.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsShortKeyContext"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_DELAY { 4000 };
constexpr int32_t MIN_DELAY { 0 };
const std::string SHORT_KEY_CLASS { "multimodalinput_short_key_class" };
const std::string SHORT_KEY_INSTANCE { "multimodalinput_short_key" };

enum class FingerprintAction : int32_t {
    DOWN = 0,
    UP = 1,
    SLIDE = 2,
    RETOUCH = 3,
    CLICK = 4,
    CANCEL = 5,
};

enum class XKeyAction : int32_t {
    X_KEY_DOWN = 0,
    X_KEY_UP = 1,
    SINGLE_CLICK = 2,
    DOUBLE_CLICK = 3,
    LONG_PRESS = 4,
};
} // namespace

JsShortKeyContext::JsShortKeyContext() : mgr_(std::make_shared<JsShortKeyManager>()) {}

napi_value JsShortKeyContext::CreateInstance(napi_env env)
{
    CALL_DEBUG_ENTER;
    napi_value global = nullptr;
    CHKRP(napi_get_global(env, &global), GET_GLOBAL);

    constexpr char className[] = "JsShortKeyContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    napi_status status = napi_define_class(env, className, sizeof(className), JsShortKeyContext::CreateJsObject,
        nullptr, sizeof(desc) / sizeof(desc[0]), nullptr, &jsClass);
    CHKRP(status, DEFINE_CLASS);

    status = napi_set_named_property(env, global, SHORT_KEY_CLASS.c_str(), jsClass);
    CHKRP(status, SET_NAMED_PROPERTY);

    napi_value jsInstance = nullptr;
    CHKRP(napi_new_instance(env, jsClass, 0, nullptr, &jsInstance), NEW_INSTANCE);
    CHKRP(napi_set_named_property(env, global, SHORT_KEY_INSTANCE.c_str(), jsInstance), SET_NAMED_PROPERTY);

    JsShortKeyContext *jsContext = nullptr;
    CHKRP(napi_unwrap(env, jsInstance, (void**)&jsContext), UNWRAP);
    CHKPP(jsContext);
    CHKRP(napi_create_reference(env, jsInstance, 1, &(jsContext->contextRef_)), CREATE_REFERENCE);

    uint32_t refCount = 0;
    if (napi_reference_ref(env, jsContext->contextRef_, &refCount) != napi_ok) {
        CHKRP(napi_delete_reference(env, jsContext->contextRef_), DELETE_REFERENCE);
        return nullptr;
    }
    return jsInstance;
}

napi_value JsShortKeyContext::CreateJsObject(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data), GET_CB_INFO);

    JsShortKeyContext *jsContext = new (std::nothrow) JsShortKeyContext();
    CHKPP(jsContext);
    napi_status status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void* data, void* hin) {
        MMI_HILOGI("jsvm ends");
        JsShortKeyContext *context = static_cast<JsShortKeyContext*>(data);
        delete context;
        context = nullptr;
    }, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsContext;
        jsContext = nullptr;
        THROWERR(env, "Failed to wrap native instance");
        return nullptr;
    }
    return thisVar;
}

JsShortKeyContext* JsShortKeyContext::GetInstance(napi_env env)
{
    CALL_DEBUG_ENTER;
    napi_value global = nullptr;
    CHKRP(napi_get_global(env, &global), GET_GLOBAL);

    bool result = false;
    CHKRP(napi_has_named_property(env, global, SHORT_KEY_INSTANCE.c_str(), &result), HAS_NAMED_PROPERTY);
    if (!result) {
        THROWERR(env, "multimodal_short_key was not found");
        return nullptr;
    }

    napi_value object = nullptr;
    CHKRP(napi_get_named_property(env, global, SHORT_KEY_INSTANCE.c_str(), &object), SET_NAMED_PROPERTY);
    if (object == nullptr) {
        THROWERR(env, "Object is nullptr");
        return nullptr;
    }

    JsShortKeyContext *instance = nullptr;
    CHKRP(napi_unwrap(env, object, (void**)&instance), UNWRAP);
    if (instance == nullptr) {
        THROWERR(env, "Instance is nullptr");
        return nullptr;
    }
    return instance;
}

std::shared_ptr<JsShortKeyManager> JsShortKeyContext::GetJsShortKeyMgr() const
{
    return mgr_;
}

napi_value JsShortKeyContext::SetKeyDownDuration(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    size_t paramsNum = 2;
    if (argc < paramsNum) {
        MMI_HILOGE("At least 2 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "businessId", "string");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_string)) {
        MMI_HILOGE("businessId parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "businessId", "string");
        return nullptr;
    }

    char businessId[MAX_STRING_LEN] = { 0 };
    size_t ret = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], businessId, MAX_STRING_LEN - 1, &ret), GET_VALUE_STRING_UTF8);
    if (ret <= 0) {
        MMI_HILOGE("Invalid businessId");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "businessId is invalid");
        return nullptr;
    }

    int32_t delay = 0;
    CHKRP(napi_get_value_int32(env, argv[1], &delay), GET_VALUE_INT32);
    if (delay < MIN_DELAY || delay > MAX_DELAY) {
        MMI_HILOGE("Invalid delay");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Delay is invalid");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_number)) {
        MMI_HILOGE("Delay parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "delay", "number");
        return nullptr;
    }
    JsShortKeyContext *jsShortKey = JsShortKeyContext::GetInstance(env);
    CHKPP(jsShortKey);
    auto jsShortKeyMgr = jsShortKey->GetJsShortKeyMgr();
    if (argc == paramsNum) {
        return jsShortKeyMgr->SetKeyDownDuration(env, businessId, delay);
    }
    if (!JsCommon::TypeOf(env, argv[paramsNum], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsShortKeyMgr->SetKeyDownDuration(env, businessId, delay, argv[paramsNum]);
}

napi_value JsShortKeyContext::GetNapiInt32(napi_env env, int32_t code)
{
    CALL_DEBUG_ENTER;
    napi_value ret = nullptr;
    CHKRP(napi_create_int32(env, code, &ret), CREATE_INT32);
    return ret;
}

napi_value JsShortKeyContext::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsShortKeyContext::Export(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    auto instance = CreateInstance(env);
    if (instance == nullptr) {
        THROWERR(env, "Failed to create instance");
        return nullptr;
    }
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("setKeyDownDuration", SetKeyDownDuration),
    };
    CHKRP(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc), DEFINE_PROPERTIES);

    napi_property_descriptor fingerprintActionArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("DOWN", GetNapiInt32(env, static_cast<int32_t>(FingerprintAction::DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("UP", GetNapiInt32(env, static_cast<int32_t>(FingerprintAction::UP))),
        DECLARE_NAPI_STATIC_PROPERTY("SLIDE", GetNapiInt32(env, static_cast<int32_t>(FingerprintAction::SLIDE))),
        DECLARE_NAPI_STATIC_PROPERTY("RETOUCH", GetNapiInt32(env, static_cast<int32_t>(FingerprintAction::RETOUCH))),
        DECLARE_NAPI_STATIC_PROPERTY("CLICK", GetNapiInt32(env, static_cast<int32_t>(FingerprintAction::CLICK))),
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL", GetNapiInt32(env, static_cast<int32_t>(FingerprintAction::CANCEL))),
    };
    napi_value fingerprintAction = nullptr;
    CHKRP(napi_define_class(env, "FingerprintAction", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(fingerprintActionArr) / sizeof(*fingerprintActionArr), fingerprintActionArr, &fingerprintAction),
        DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "FingerprintAction", fingerprintAction), SET_NAMED_PROPERTY);

    napi_property_descriptor xKeyActionArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("X_KEY_DOWN", GetNapiInt32(env, static_cast<int32_t>(XKeyAction::X_KEY_DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("X_KEY_UP", GetNapiInt32(env, static_cast<int32_t>(XKeyAction::X_KEY_UP))),
        DECLARE_NAPI_STATIC_PROPERTY("SINGLE_CLICK", GetNapiInt32(env, static_cast<int32_t>(XKeyAction::SINGLE_CLICK))),
        DECLARE_NAPI_STATIC_PROPERTY("DOUBLE_CLICK", GetNapiInt32(env, static_cast<int32_t>(XKeyAction::DOUBLE_CLICK))),
        DECLARE_NAPI_STATIC_PROPERTY("LONG_PRESS", GetNapiInt32(env, static_cast<int32_t>(XKeyAction::LONG_PRESS))),
    };
    napi_value xKeyAction = nullptr;
    CHKRP(napi_define_class(env, "XKeyAction", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(xKeyActionArr) / sizeof(*xKeyActionArr), xKeyActionArr, &xKeyAction),
        DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "XKeyAction", xKeyAction), SET_NAMED_PROPERTY);
    return exports;
}
} // namespace MMI
} // namespace OHOS
