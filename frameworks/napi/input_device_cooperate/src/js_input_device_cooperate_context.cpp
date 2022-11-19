/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_input_device_cooperate_context.h"

#include <cstddef>
#include <cstdint>

#include "define_multimodal.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"
#include "util_napi_error.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputDeviceCooperateContext" };
constexpr const char *INPUT_DEVICE_CLASS = "multimodalinput_input_device_class";
constexpr const char *INPUT_DEVICE_COOPERATE = "multimodal_input_device_cooperate";
} // namespace

JsInputDeviceCooperateContext::JsInputDeviceCooperateContext()
    : mgr_(std::make_shared<JsInputDeviceCooperateManager>()) {}

JsInputDeviceCooperateContext::~JsInputDeviceCooperateContext()
{
    std::lock_guard<std::mutex> guard(mutex_);
    auto jsInputDeviceMgr = mgr_;
    mgr_.reset();
    if (jsInputDeviceMgr != nullptr) {
        jsInputDeviceMgr->ResetEnv();
    }
}

napi_value JsInputDeviceCooperateContext::Export(napi_env env, napi_value exports)
{
    CALL_INFO_TRACE;
    auto instance = CreateInstance(env);
    if (instance == nullptr) {
        MMI_HILOGE("instance is nullptr");
        return nullptr;
    }
    DeclareDeviceCooperateInterface(env, exports);
    DeclareDeviceCooperateData(env, exports);
    return exports;
}

napi_value JsInputDeviceCooperateContext::Enable(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = 2;
    napi_value argv[2] = {};
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc == 0) {
        MMI_HILOGE("Wrong number of parameters");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "enable", "boolean");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[0], napi_boolean)) {
        MMI_HILOGE("Thr first parameter is not boolean");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "enable", "boolean");
        return nullptr;
    }
    bool enable = false;
    CHKRP(env, napi_get_value_bool(env, argv[0], &enable), GET_BOOL);

    JsInputDeviceCooperateContext *jsDev = JsInputDeviceCooperateContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceCooperateMgr();
    if (argc == 1) {
        return jsInputDeviceMgr->Enable(env, enable);
    }
    if (!UtilNapi::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("The second parameter is not function");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->Enable(env, enable, argv[1]);
}

napi_value JsInputDeviceCooperateContext::Start(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = 3;
    napi_value argv[3] = {};
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc < 2) {
        MMI_HILOGE("Wrong number of parameters");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "sinkDeviceDescriptor", "string");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[0], napi_string)) {
        MMI_HILOGE("Thr first parameter is not boolean");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "sinkDeviceDescriptor", "string");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[1], napi_number)) {
        MMI_HILOGE("The second parameter is not number");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "srcInputDeviceId", "number");
        return nullptr;
    }
    char sinkDeviceDescriptor[MAX_STRING_LEN] = {};
    int32_t srcInputDeviceId = 0;
    size_t length = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[0], sinkDeviceDescriptor,
        sizeof(sinkDeviceDescriptor), &length), GET_STRING);
    std::string sinkDeviceDescriptor_ = sinkDeviceDescriptor;
    CHKRP(env, napi_get_value_int32(env, argv[1], &srcInputDeviceId), GET_INT32);

    JsInputDeviceCooperateContext *jsDev = JsInputDeviceCooperateContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceCooperateMgr();
    if (argc == 2) {
        return jsInputDeviceMgr->Start(env, sinkDeviceDescriptor, srcInputDeviceId);
    }
    if (!UtilNapi::TypeOf(env, argv[2], napi_function)) {
        MMI_HILOGE("Thr third parameter is not function");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->Start(env, std::string(sinkDeviceDescriptor), srcInputDeviceId, argv[2]);
}

napi_value JsInputDeviceCooperateContext::Stop(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = 1;
    napi_value argv[1] = {};
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    JsInputDeviceCooperateContext *jsDev = JsInputDeviceCooperateContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceCooperateMgr();
    if (argc == 0) {
        return jsInputDeviceMgr->Stop(env);
    }
    if (!UtilNapi::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("The first parameter is not function");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->Stop(env, argv[0]);
}

napi_value JsInputDeviceCooperateContext::GetState(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = 2;
    napi_value argv[2] = {};
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc == 0) {
        MMI_HILOGE("Wrong number of parameters");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "deviceDescriptor", "string");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[0], napi_string)) {
        MMI_HILOGE("The first parameter is not string");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "deviceDescriptor", "string");
        return nullptr;
    }
    char deviceDescriptor[MAX_STRING_LEN] = { 0 };
    size_t length = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[0], deviceDescriptor,
        sizeof(deviceDescriptor), &length), GET_STRING);
    std::string deviceDescriptor_ = deviceDescriptor;

    JsInputDeviceCooperateContext *jsDev = JsInputDeviceCooperateContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceCooperateMgr();
    if (argc == 1) {
        return jsInputDeviceMgr->GetState(env, deviceDescriptor_);
    }
    if (!UtilNapi::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("The second parameter is not function");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->GetState(env, deviceDescriptor_, argv[1]);
}

napi_value JsInputDeviceCooperateContext::On(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = 2;
    napi_value argv[2] = {};
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc == 0) {
        MMI_HILOGE("Wrong number of parameters");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[0], napi_string)) {
        MMI_HILOGE("The first parameter is not string");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }
    char type[MAX_STRING_LEN] = {};
    size_t length = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[0], type, sizeof(type), &length), GET_STRING);
    if (std::strcmp(type, "cooperation") != 0) {
        THROWERR(env, "Register listener failed, the first parameter is invalid");
        MMI_HILOGE("Register listener failed, the first parameter is invalid");
        return nullptr;
    }
    JsInputDeviceCooperateContext *jsDev = JsInputDeviceCooperateContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceCooperateMgr();
    if (!UtilNapi::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("The seocond parameter is not function");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    jsInputDeviceMgr->RegisterListener(env, type, argv[1]);
    return nullptr;
}

napi_value JsInputDeviceCooperateContext::Off(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = 2;
    napi_value argv[2] = {};
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc == 0) {
        MMI_HILOGE("Wrong number of parameters");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[0], napi_string)) {
        MMI_HILOGE("The first parameter is not string");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }
    char type[MAX_STRING_LEN] = {};
    size_t length = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[0], type, sizeof(type), &length), GET_STRING);
    std::string type_ = type;

    JsInputDeviceCooperateContext *jsDev = JsInputDeviceCooperateContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceCooperateMgr();
    if (argc == 1) {
        jsInputDeviceMgr->UnregisterListener(env, type_);
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("The second parameter is not function");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    jsInputDeviceMgr->UnregisterListener(env, type_, argv[1]);
    return nullptr;
}

std::shared_ptr<JsInputDeviceCooperateManager> JsInputDeviceCooperateContext::GetJsInputDeviceCooperateMgr()
{
    std::lock_guard<std::mutex> guard(mutex_);
    return mgr_;
}

napi_value JsInputDeviceCooperateContext::CreateInstance(napi_env env)
{
    CALL_INFO_TRACE;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), GET_GLOBAL);

    constexpr char className[] = "JsInputDeviceCooperateContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    napi_status status = napi_define_class(env, className, sizeof(className),
        JsInputDeviceCooperateContext::JsConstructor, nullptr, sizeof(desc) / sizeof(desc[0]), nullptr, &jsClass);
    CHKRP(env, status, DEFINE_CLASS);

    status = napi_set_named_property(env, global, INPUT_DEVICE_CLASS, jsClass);
    CHKRP(env, status, SET_NAMED_PROPERTY);

    napi_value jsInstance = nullptr;
    CHKRP(env, napi_new_instance(env, jsClass, 0, nullptr, &jsInstance), NEW_INSTANCE);
    CHKRP(env, napi_set_named_property(env, global, INPUT_DEVICE_COOPERATE, jsInstance),
        SET_NAMED_PROPERTY);

    JsInputDeviceCooperateContext *jsContext = nullptr;
    CHKRP(env, napi_unwrap(env, jsInstance, (void**)&jsContext), UNWRAP);
    CHKPP(jsContext);
    CHKRP(env, napi_create_reference(env, jsInstance, 1, &(jsContext->contextRef_)), CREATE_REFERENCE);

    uint32_t refCount = 0;
    status = napi_reference_ref(env, jsContext->contextRef_, &refCount);
    if (status != napi_ok) {
        MMI_HILOGE("ref is nullptr");
        napi_delete_reference(env, jsContext->contextRef_);
        return nullptr;
    }
    return jsInstance;
}

napi_value JsInputDeviceCooperateContext::JsConstructor(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data), GET_CB_INFO);

    JsInputDeviceCooperateContext *jsContext = new (std::nothrow) JsInputDeviceCooperateContext();
    CHKPP(jsContext);
    napi_status status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void *data, void *hin) {
        MMI_HILOGI("jsvm ends");
        JsInputDeviceCooperateContext *context = static_cast<JsInputDeviceCooperateContext*>(data);
        delete context;
    }, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsContext;
        MMI_HILOGE("%{public}s failed", std::string(WRAP).c_str());
        auto infoTemp = std::string(__FUNCTION__) + ": " + std::string(WRAP) + " failed";
        napi_throw_error(env, nullptr, infoTemp.c_str());
        return nullptr;
    }
    return thisVar;
}

JsInputDeviceCooperateContext *JsInputDeviceCooperateContext::GetInstance(napi_env env)
{
    CALL_INFO_TRACE;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), GET_GLOBAL);

    bool result = false;
    CHKRP(env, napi_has_named_property(env, global, INPUT_DEVICE_COOPERATE, &result), HAS_NAMED_PROPERTY);
    if (!result) {
        MMI_HILOGE("multimodal_input_device_cooperate was not found");
        return nullptr;
    }

    napi_value object = nullptr;
    CHKRP(env, napi_get_named_property(env, global, INPUT_DEVICE_COOPERATE, &object), GET_NAMED_PROPERTY);
    if (object == nullptr) {
        MMI_HILOGE("object is nullptr");
        return nullptr;
    }

    JsInputDeviceCooperateContext *instance = nullptr;
    CHKRP(env, napi_unwrap(env, object, (void**)&instance), UNWRAP);
    if (instance == nullptr) {
        MMI_HILOGE("instance is nullptr");
        return nullptr;
    }
    return instance;
}

void JsInputDeviceCooperateContext::DeclareDeviceCooperateInterface(napi_env env, napi_value exports)
{
    napi_value infoStart = nullptr;
    CHKRV(env, napi_create_int32(env, static_cast<int32_t>(CooperationMessage::INFO_START), &infoStart),
        CREATE_INT32);
    napi_value infoSuccess = nullptr;
    CHKRV(env, napi_create_int32(env, static_cast<int32_t>(CooperationMessage::INFO_SUCCESS), &infoSuccess),
        CREATE_INT32);
    napi_value infoFail = nullptr;
    CHKRV(env, napi_create_int32(env, static_cast<int32_t>(CooperationMessage::INFO_FAIL), &infoFail),
        CREATE_INT32);
    napi_value stateOn = nullptr;
    CHKRV(env, napi_create_int32(env, static_cast<int32_t>(CooperationMessage::STATE_ON), &stateOn),
        CREATE_INT32);
    napi_value stateOff = nullptr;
    CHKRV(env, napi_create_int32(env, static_cast<int32_t>(CooperationMessage::STATE_OFF), &stateOff),
        CREATE_INT32);

    napi_property_descriptor msg[] = {
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_INFO_START", infoStart),
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_INFO_SUCCESS", infoSuccess),
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_INFO_FAIL", infoFail),
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_STATE_ON", stateOn),
        DECLARE_NAPI_STATIC_PROPERTY("MSG_COOPERATE_STATE_OFF", stateOff),
    };

    napi_value eventMsg = nullptr;
    CHKRV(env, napi_define_class(env, "EventMsg", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(msg) / sizeof(*msg), msg, &eventMsg), DEFINE_CLASS);
    CHKRV(env, napi_set_named_property(env, exports, "EventMsg", eventMsg), SET_NAMED_PROPERTY);
}

void JsInputDeviceCooperateContext::DeclareDeviceCooperateData(napi_env env, napi_value exports)
{
    napi_property_descriptor functions[] = {
        DECLARE_NAPI_STATIC_FUNCTION("enable", Enable),
        DECLARE_NAPI_STATIC_FUNCTION("start", Start),
        DECLARE_NAPI_STATIC_FUNCTION("stop", Stop),
        DECLARE_NAPI_STATIC_FUNCTION("getState", GetState),
        DECLARE_NAPI_STATIC_FUNCTION("on", On),
        DECLARE_NAPI_STATIC_FUNCTION("off", Off),
    };
    CHKRV(env, napi_define_properties(env, exports,
        sizeof(functions) / sizeof(*functions), functions), DEFINE_PROPERTIES);
}

napi_value JsInputDeviceCooperateContext::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value args[1] = {};
    napi_value result = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, &argc, args, &result, &data), GET_CB_INFO);
    return result;
}
} // namespace MMI
} // namespace OHOS
