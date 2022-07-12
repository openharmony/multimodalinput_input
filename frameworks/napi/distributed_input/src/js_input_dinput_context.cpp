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

#include "js_input_dinput_context.h"
#include "util_napi.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsInputDinputContext" };
constexpr uint32_t ARGV_FIRST = 0;
constexpr uint32_t ARGV_SECOND = 1;
constexpr uint32_t ARGV_THIRD = 2;
constexpr uint32_t ARGC_NUM_1 = 1;
constexpr uint32_t ARGC_NUM_2 = 2;
constexpr uint32_t ARGC_NUM_3 = 3;
constexpr uint32_t INIT_REF_COUNT = 1;
constexpr size_t MAX_STRING_LEN = 1024;
const std::string GET_GLOBLE = "napi_get_global";
const std::string DEFINE_CLASS = "napi_define_class";
const std::string WRAP = "napi_wrap";
const std::string UNWRAP = "napi_unwrap";
const std::string NEW_INSTANCE = "napi_new_instance";
const std::string SET_NAMED_PROPERTY = "napi_set_named_property";
const std::string CREATE_REFERENCE = "napi_create_reference";
const std::string REFERENCE_REF = "napi_create_reference";
const std::string GET_CB_INFO = "napi_get_cb_info";
const std::string HAS_NAMED_PROPERTY = "napi_has_named_property";
const std::string GET_INT32 = "napi_get_value_int32";
const std::string DEFINE_PROPERTIES = "napi_define_properties";
const std::string GET_STRING_UTF8 = "napi_get_value_string_utf8";
const std::string GET_ARRAY_LENGTH = "napi_get_array_length";
const std::string GET_ELEMENT = "napi_get_element";
const std::string GET_BOOL = "napi_get_boolean";
const std::string CREATE_INT32 = "napi_create_int32";
const std::string TYPEOF = "napi_typeof";

napi_ref inputAbilityTypeEnumConstructor_ = nullptr;
} // namespace

napi_value JsInputDinputContext::CreateInstance(napi_env env)
{
    CALL_LOG_ENTER;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), GET_GLOBLE);
    constexpr char className[] = "JsInputDinputContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    napi_status status = napi_define_class(env, className, sizeof(className),
        JsInputDinputContext::JsConstructor, nullptr, sizeof(desc) / sizeof(desc[0]), nullptr, &jsClass);
    CHKRP(env, status, DEFINE_CLASS);
    status = napi_set_named_property(env, global, "multimodalinput_input_dinput_class", jsClass);
    CHKRP(env, status, SET_NAMED_PROPERTY);
    napi_value jsInstance = nullptr;
    CHKRP(env, napi_new_instance(env, jsClass, 0, nullptr, &jsInstance), NEW_INSTANCE);
    CHKRP(env, napi_set_named_property(env, global, "multimodal_input_dinput", jsInstance), SET_NAMED_PROPERTY);

    JsInputDinputContext *jsContext = nullptr;
    status = napi_unwrap(env, jsInstance, (void**)&jsContext);
    CHKPP(jsContext);
    CHKRP(env, napi_create_reference(env, jsInstance, 1, &(jsContext->contextRef_)), CREATE_REFERENCE);
    uint32_t refCount = 0;
    CHKRP(env, napi_reference_ref(env, jsContext->contextRef_, &refCount), REFERENCE_REF);
    return jsInstance;
}

napi_value JsInputDinputContext::JsConstructor(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data), GET_CB_INFO);
    JsInputDinputContext *jsContext = new (std::nothrow) JsInputDinputContext();
    CHKPP(jsContext);
    CHKPP(data);
    napi_status status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void* data, void* hin) {
        MMI_HILOGI("jsvm ends");
        CHKPL(data);
        auto context = static_cast<JsInputDinputContext*>(data);
        delete context;
    }, nullptr, nullptr);
    CHKRP(env, status, WRAP);
    return thisVar;
}

JsInputDinputContext* JsInputDinputContext::GetInstance(napi_env env)
{
    CALL_LOG_ENTER;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), GET_GLOBLE);
    bool result = false;
    CHKRP(env, napi_has_named_property(env, global, "multimodal_input_dinput", &result), HAS_NAMED_PROPERTY);
    napi_value object = nullptr;
    CHKRP(env, napi_get_named_property(env, global, "multimodal_input_dinput", &object), SET_NAMED_PROPERTY);
    if (object == nullptr) {
        THROWERR(env, "object is nullptr");
        return nullptr;
    }
    JsInputDinputContext *instance = nullptr;
    CHKRP(env, napi_unwrap(env, object, (void**)&instance), UNWRAP);
    if (instance == nullptr) {
        THROWERR(env, "instance is nullptr");
        return nullptr;
    }
    return instance;
}

std::shared_ptr<JsInputDinputManager> JsInputDinputContext::GetJsInputDinputMgr() const
{
    return mgr_;
}

napi_value JsInputDinputContext::PrepareRemoteInput(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    std::string deviceId;
    napi_ref callBackRef = nullptr;
    if (GetParameter(env, info, deviceId, callBackRef) != nullptr) {
        JsInputDinputContext *jsContext = JsInputDinputContext::GetInstance(env);
        CHKPP(jsContext);
        auto jsInputDinputMgr = jsContext->GetJsInputDinputMgr();
        CHKPP(jsInputDinputMgr);
        return jsInputDinputMgr->PrepareRemoteInput(env, deviceId, callBackRef);
    }
    return nullptr;
}

napi_value JsInputDinputContext::UnprepareRemoteInput(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    std::string deviceId;
    napi_ref callBackRef = nullptr;
    if (GetParameter(env, info, deviceId, callBackRef) != nullptr) {
        JsInputDinputContext *jsContext = JsInputDinputContext::GetInstance(env);
        CHKPP(jsContext);
        auto jsInputDinputMgr = jsContext->GetJsInputDinputMgr();
        CHKPP(jsInputDinputMgr);
        return jsInputDinputMgr->UnprepareRemoteInput(env, deviceId, callBackRef);
    }
    return nullptr;
}

napi_value JsInputDinputContext::StartRemoteInput(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    std::string deviceId;
    std::vector<uint32_t> inputAbility;
    napi_ref callBackRef = nullptr;
    if (GetParameter(env, info, deviceId, inputAbility, callBackRef) != nullptr) {
        JsInputDinputContext *jsContext = JsInputDinputContext::GetInstance(env);
        CHKPP(jsContext);
        auto jsInputDinputMgr = jsContext->GetJsInputDinputMgr();
        CHKPP(jsInputDinputMgr);
        return jsInputDinputMgr->StartRemoteInput(env, deviceId, inputAbility, callBackRef);
    }
    return nullptr;
}

napi_value JsInputDinputContext::StopRemoteInput(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    std::string deviceId;
    std::vector<uint32_t> inputAbility;
    napi_ref callBackRef = nullptr;
    if (GetParameter(env, info, deviceId, inputAbility, callBackRef) != nullptr) {
        JsInputDinputContext *jsContext = JsInputDinputContext::GetInstance(env);
        CHKPP(jsContext);
        auto jsInputDinputMgr = jsContext->GetJsInputDinputMgr();
        CHKPP(jsInputDinputMgr);
        return jsInputDinputMgr->StopRemoteInput(env, deviceId, inputAbility, callBackRef);
    }
    return nullptr;
}

napi_value JsInputDinputContext::GetRemoteInputAbility(napi_env env, napi_callback_info info)
{
    CALL_LOG_ENTER;
    std::string deviceId;
    napi_ref callBackRef = nullptr;
    if (GetParameter(env, info, deviceId, callBackRef) != nullptr) {
        JsInputDinputContext *jsContext = JsInputDinputContext::GetInstance(env);
        CHKPP(jsContext);
        auto jsInputDinputMgr = jsContext->GetJsInputDinputMgr();
        CHKPP(jsInputDinputMgr);
        return jsInputDinputMgr->GetRemoteInputAbility(env, deviceId, callBackRef);
    }
    return nullptr;
}

napi_value JsInputDinputContext::GetParameter(napi_env env, napi_callback_info info, napi_ref& first)
{
    CALL_LOG_ENTER;
    size_t argc = ARGC_NUM_1;
    napi_value argv[ARGC_NUM_1];
    napi_value ret = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    CHKRP(env, napi_create_int32(env, argc, &ret), CREATE_INT32);
    if (argc > ARGC_NUM_1) {
        THROWERR(env, "parameters count error");
        return nullptr;
    }
    if (argc == 0) {
        first = nullptr;
        return ret;
    }
    if (!TypeOf(env, argv[ARGV_FIRST], napi_function)) {
        THROWERR(env, "The first parameter type is incorrect");
        return nullptr;
    }
    CHKRP(env, napi_create_reference(env, argv[ARGV_FIRST], INIT_REF_COUNT, &first), CREATE_REFERENCE);
    return ret;
}

napi_value JsInputDinputContext::GetParameter(napi_env env, napi_callback_info info,
    std::string& first, napi_ref& second)
{
    CALL_LOG_ENTER;
    size_t argc = ARGC_NUM_2;
    napi_value argv[ARGC_NUM_2];
    napi_value ret = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    CHKRP(env, napi_create_int32(env, argc, &ret), CREATE_INT32);
    if (argc > ARGC_NUM_2 || argc < ARGC_NUM_1) {
        THROWERR(env, "parameters count error");
        return nullptr;
    }
    if (!TypeOf(env, argv[ARGV_FIRST], napi_string)) {
        THROWERR(env, "The first parameter type is incorrect");
        return nullptr;
    }
    char deviceId[MAX_STRING_LEN] = { 0 };
    size_t typeLen = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[ARGV_FIRST], deviceId,
        MAX_STRING_LEN - 1, &typeLen), GET_STRING_UTF8);
    first = deviceId;
    if (argc == ARGC_NUM_1) {
        second = nullptr;
        return ret;
    }
    if (!TypeOf(env, argv[ARGV_SECOND], napi_function)) {
        THROWERR(env, "The second parameter type is incorrect");
        return nullptr;
    }
    CHKRP(env, napi_create_reference(env, argv[ARGV_SECOND], INIT_REF_COUNT, &second), CREATE_REFERENCE);
    return ret;
}

napi_value JsInputDinputContext::GetParameter(napi_env env, napi_callback_info info,
    int32_t& first, int32_t& second, napi_ref& third)
{
    CALL_LOG_ENTER;
    size_t argc = ARGC_NUM_3;
    napi_value argv[ARGC_NUM_3];
    napi_value ret = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    CHKRP(env, napi_create_int32(env, argc, &ret), CREATE_INT32);
    if (argc > ARGC_NUM_3 || argc < ARGC_NUM_2) {
        THROWERR(env, "parameters count error");
        return nullptr;
    }
    if (!TypeOf(env, argv[ARGV_FIRST], napi_number)) {
        THROWERR(env, "The first parameter type is incorrect");
        return nullptr;
    }
    if (!TypeOf(env, argv[ARGV_SECOND], napi_number)) {
        THROWERR(env, "The second parameter type is incorrect");
        return nullptr;
    }
    napi_get_value_int32(env, argv[ARGV_FIRST], &first);
    napi_get_value_int32(env, argv[ARGV_SECOND], &second);
    if (argc == ARGC_NUM_2) {
        third = nullptr;
        return ret;
    }
    if (!TypeOf(env, argv[ARGV_THIRD], napi_function)) {
        THROWERR(env, "The third parameter type is incorrect");
        return nullptr;
    }
    CHKRP(env, napi_create_reference(env, argv[ARGV_THIRD], INIT_REF_COUNT, &third), CREATE_REFERENCE);
    return ret;
}

napi_value JsInputDinputContext::GetParameter(napi_env env, napi_callback_info info,
    std::string& first, std::vector<uint32_t>& second, napi_ref& third)
{
    CALL_LOG_ENTER;
    size_t argc = ARGC_NUM_3;
    napi_value argv[ARGC_NUM_3];
    napi_value ret = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    CHKRP(env, napi_create_int32(env, argc, &ret), CREATE_INT32);
    if (argc > ARGC_NUM_3 || argc < ARGC_NUM_2) {
        THROWERR(env, "parameters count error");
        return nullptr;
    }
    if (!TypeOf(env, argv[ARGV_FIRST], napi_string)) {
        THROWERR(env, "The first parameter type is incorrect");
        return nullptr;
    }
    char deviceId[MAX_STRING_LEN] = { 0 };
    size_t typeLen = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[ARGV_FIRST], deviceId,
        MAX_STRING_LEN - 1, &typeLen), GET_STRING_UTF8);
    first = deviceId;

    uint32_t arrayLength = 0;
    CHKRP(env, napi_get_array_length(env, argv[ARGV_SECOND], &arrayLength), GET_ARRAY_LENGTH);
    if (arrayLength <= 0) {
        THROWERR(env, "length is incorrect");
        return nullptr;
    }
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value inputAbility = nullptr;
        CHKRP(env, napi_get_element(env, argv[ARGV_SECOND], i, &inputAbility), GET_ELEMENT);
        if (!TypeOf(env, inputAbility, napi_number)) {
            THROWERR(env, "The numeric parameter type is incorrect");
            return nullptr;
        }
        int32_t value0 = 0;
        CHKRP(env, napi_get_value_int32(env, inputAbility, &value0), GET_INT32);
        second.push_back(value0);
    }
    if (argc == ARGC_NUM_2) {
        third = nullptr;
        return ret;
    }
    if (!TypeOf(env, argv[ARGV_THIRD], napi_function)) {
        THROWERR(env, "The function parameter type is incorrect");
        return nullptr;
    }
    CHKRP(env, napi_create_reference(env, argv[ARGV_THIRD], INIT_REF_COUNT, &third), CREATE_REFERENCE);
    return ret;
}

bool JsInputDinputContext::TypeOf(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valueType = napi_undefined;
    CHKRF(env, napi_typeof(env, value, &valueType), TYPEOF);
    return valueType == type;
}

napi_value JsInputDinputContext::EnumTypeConstructor(napi_env env, napi_callback_info info)
{
    size_t argc = 0;
    napi_value args[ARGC_NUM_1] = { 0 };
    napi_value res = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, &argc, args, &res, &data), GET_CB_INFO);
    MMI_HILOGD("Constructed successfully");
    return res;
}

napi_value JsInputDinputContext::Init(napi_env env, napi_value exports)
{
    CALL_LOG_ENTER;
    auto instance = CreateInstance(env);
    if (instance == nullptr) {
        napi_throw_error(env, nullptr, "JsInputDeviceContext: failed to create instance");
        MMI_HILOGW("failed to create instance");
        return nullptr;
    }
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("prepareRemoteInput", PrepareRemoteInput),
        DECLARE_NAPI_FUNCTION("unprepareRemoteInput", UnprepareRemoteInput),
        DECLARE_NAPI_FUNCTION("startRemoteInput", StartRemoteInput),
        DECLARE_NAPI_FUNCTION("stopRemoteInput", StopRemoteInput),
        DECLARE_NAPI_FUNCTION("getRemoteInputAbility", GetRemoteInputAbility),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

napi_value JsInputDinputContext::InitInputAbilityTypeEnum(napi_env env, napi_value exports)
{
    napi_value mouse;
    napi_value keyboard;
    napi_value touchpad;

    int32_t refCount = 1;
    napi_create_uint32(env, static_cast<uint32_t>(InputAbilityType::MOUSE), &mouse);
    napi_create_uint32(env, static_cast<uint32_t>(InputAbilityType::KEYBOARD), &keyboard);
    napi_create_uint32(env, static_cast<uint32_t>(InputAbilityType::TOUCHPAD), &touchpad);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("MOUSE", mouse),
        DECLARE_NAPI_STATIC_PROPERTY("KEYBOARD", keyboard),
        DECLARE_NAPI_STATIC_PROPERTY("TOUCHPAD", touchpad),
    };

    napi_value result = nullptr;
    napi_define_class(env, "InputAbilityType", NAPI_AUTO_LENGTH, EnumTypeConstructor,
        nullptr, sizeof(desc) / sizeof(*desc), desc, &result);
    napi_create_reference(env, result, refCount, &inputAbilityTypeEnumConstructor_);
    napi_set_named_property(env, exports, "InputAbilityType", result);
    return exports;
}

napi_value JsInputDinputContext::Export(napi_env env, napi_value exports)
{
    JsInputDinputContext::Init(env, exports);
    JsInputDinputContext::InitInputAbilityTypeEnum(env, exports);
    return exports;
}
} // namespace MMI
} // namespace OHOS