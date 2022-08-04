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
constexpr size_t MAX_STRING_LEN = 32;
const std::string CHANGED_TYPE = "change";

const std::string GET_GLOBAL = "napi_get_global";
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
const std::string CREATE_INT32 = "napi_create_int32";

enum KeyboardType {
    NONE = 0,
    UNKNOWN = 1,
    ALPHABETIC_KEYBOARD = 2,
    DIGITAL_KEYBOARD = 3,
    HANDWRITING_PEN = 4,
    REMOTE_CONTROL = 5,
};
} // namespace

JsInputDeviceContext::JsInputDeviceContext()
{
    mgr_ = std::make_shared<JsInputDeviceManager>();
    CHKPL(mgr_);
}

JsInputDeviceContext::~JsInputDeviceContext()
{
    std::lock_guard<std::mutex> guard(mtx_);
    auto jsInputDeviceMgr = mgr_;
    mgr_.reset();
    if (jsInputDeviceMgr) {
        jsInputDeviceMgr->ResetEnv();
    }
}

napi_value JsInputDeviceContext::CreateInstance(napi_env env)
{
    CALL_DEBUG_ENTER;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), GET_GLOBAL);

    constexpr char className[] = "JsInputDeviceContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    napi_status status = napi_define_class(env, className, sizeof(className), JsInputDeviceContext::JsConstructor,
                                           nullptr, sizeof(desc) / sizeof(desc[0]), nullptr, &jsClass);
    CHKRP(env, status, DEFINE_CLASS);

    status = napi_set_named_property(env, global, "multimodalinput_input_device_class", jsClass);
    CHKRP(env, status, SET_NAMED_PROPERTY);

    napi_value jsInstance = nullptr;
    CHKRP(env, napi_new_instance(env, jsClass, 0, nullptr, &jsInstance), NEW_INSTANCE);
    CHKRP(env, napi_set_named_property(env, global, "multimodal_input_device", jsInstance), SET_NAMED_PROPERTY);

    JsInputDeviceContext *jsContext = nullptr;
    CHKRP(env, napi_unwrap(env, jsInstance, (void**)&jsContext), UNWRAP);
    CHKPP(jsContext);
    CHKRP(env, napi_create_reference(env, jsInstance, 1, &(jsContext->contextRef_)), CREATE_REFERENCE);

    uint32_t refCount = 0;
    CHKRP(env, napi_reference_ref(env, jsContext->contextRef_, &refCount), REFERENCE_REF);
    return jsInstance;
}

napi_value JsInputDeviceContext::JsConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data), GET_CB_INFO);

    JsInputDeviceContext *jsContext = new (std::nothrow) JsInputDeviceContext();
    CHKPP(jsContext);
    napi_status status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void* data, void* hin) {
        MMI_HILOGI("jsvm ends");
        JsInputDeviceContext *context = static_cast<JsInputDeviceContext*>(data);
        delete context;
    }, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsContext;
        THROWERR(env, "Failed to wrap native instance");
        return nullptr;
    }
    return thisVar;
}

JsInputDeviceContext* JsInputDeviceContext::GetInstance(napi_env env)
{
    CALL_DEBUG_ENTER;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), GET_GLOBAL);

    bool result = false;
    CHKRP(env, napi_has_named_property(env, global, "multimodal_input_device", &result), HAS_NAMED_PROPERTY);
    if (!result) {
        THROWERR(env, "multimodal_input_device was not found");
        return nullptr;
    }

    napi_value object = nullptr;
    CHKRP(env, napi_get_named_property(env, global, "multimodal_input_device", &object), SET_NAMED_PROPERTY);
    if (object == nullptr) {
        THROWERR(env, "object is nullptr");
        return nullptr;
    }

    JsInputDeviceContext *instance = nullptr;
    CHKRP(env, napi_unwrap(env, object, (void**)&instance), UNWRAP);
    if (instance == nullptr) {
        THROWERR(env, "instance is nullptr");
        return nullptr;
    }
    return instance;
}

std::shared_ptr<JsInputDeviceManager> JsInputDeviceContext::GetJsInputDeviceMgr() const
{
    return mgr_;
}

napi_value JsInputDeviceContext::On(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc != 2) {
        THROWERR(env, "the number of parameters is incorrect");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_string)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }

    char eventType[MAX_STRING_LEN] = {0};
    size_t ret = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[0], eventType, MAX_STRING_LEN - 1, &ret), GET_STRING_UTF8);
    std::string type = eventType;
    if (type != CHANGED_TYPE) {
        THROWERR(env, "event type is wrong");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        THROWERR(env, "The second parameter type is wrong");
        return nullptr;
    }

    JsInputDeviceContext *jsIds = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsIds->GetJsInputDeviceMgr();
    jsInputDeviceMgr->RegisterDevListener(env, type, argv[1]);
    return nullptr;
}

napi_value JsInputDeviceContext::Off(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > 2) {
        THROWERR(env, "the number of parameters is incorrect");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_string)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }

    char eventType[MAX_STRING_LEN] = {0};
    size_t ret = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[0], eventType, MAX_STRING_LEN - 1, &ret), GET_STRING_UTF8);
    std::string type = eventType;
    if (type != CHANGED_TYPE) {
        THROWERR(env, "event type is wrong");
        return nullptr;
    }

    JsInputDeviceContext *jsIds = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsIds->GetJsInputDeviceMgr();
    if (argc == 1) {
        jsInputDeviceMgr->UnregisterDevListener(env, type);
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        THROWERR(env, "The second parameter type is wrong");
        return nullptr;
    }
    jsInputDeviceMgr->UnregisterDevListener(env, type, argv[1]);
    return nullptr;
}

napi_value JsInputDeviceContext::GetDeviceIds(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc > 1) {
        THROWERR(env, "too many parameters");
        return nullptr;
    }

    JsInputDeviceContext *jsIds = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsIds->GetJsInputDeviceMgr();
    if (argc == 0) {
        return jsInputDeviceMgr->GetDeviceIds(env);
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_function)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }
    return jsInputDeviceMgr->GetDeviceIds(env, argv[0]);
}

napi_value JsInputDeviceContext::GetDevice(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > 2) {
        THROWERR(env, "the number of parameters is not as expected");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }
    int32_t id = 0;
    CHKRP(env, napi_get_value_int32(env, argv[0], &id), GET_INT32);

    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc == 1) {
        return jsInputDeviceMgr->GetDevice(env, id);
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        THROWERR(env, "The second parameter type is wrong");
        return nullptr;
    }
    return jsInputDeviceMgr->GetDevice(env, id, argv[1]);
}

napi_value JsInputDeviceContext::SupportKeys(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 2 || argc > 3) {
        THROWERR(env, "parameter number error");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }
    int32_t deviceId = 0;
    CHKRP(env, napi_get_value_int32(env, argv[0], &deviceId), GET_INT32);

    if (!JsUtil::TypeOf(env, argv[1], napi_object)) {
        THROWERR(env, "The second parameter type is wrong");
        return nullptr;
    }
    uint32_t size = 0;
    CHKRP(env, napi_get_array_length(env, argv[1], &size), GET_ARRAY_LENGTH);
    if (size < 1 || size > 5) {
        THROWERR(env, "the number of parameters is incorrect, the range is 1 to 5");
        return nullptr;
    }

    int32_t data = 0;
    std::vector<int32_t> keyCodes;
    for (uint32_t i = 0; i < size; ++i) {
        napi_value keyValue = nullptr;
        CHKRP(env, napi_get_element(env, argv[1], i, &keyValue), GET_ELEMENT);
        if (!JsUtil::TypeOf(env, keyValue, napi_number)) {
            THROWERR(env, "Parameter type error");
            return nullptr;
        }
        CHKRP(env, napi_get_value_int32(env, keyValue, &data), GET_INT32);
        keyCodes.push_back(data);
    }

    JsInputDeviceContext *jsContext = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsContext->GetJsInputDeviceMgr();
    if (argc == 2) {
        return jsInputDeviceMgr->SupportKeys(env, deviceId, keyCodes);
    }
    if (!JsUtil::TypeOf(env, argv[2], napi_function)) {
        THROWERR(env, "The third parameter type is wrong");
        return nullptr;
    }
    return jsInputDeviceMgr->SupportKeys(env, deviceId, keyCodes, argv[2]);
}

napi_value JsInputDeviceContext::GetKeyboardType(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > 2) {
        THROWERR(env, "The number of parameters is not as expected");
        return nullptr;
    }

    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }
    int32_t id = 0;
    CHKRP(env, napi_get_value_int32(env, argv[0], &id), GET_INT32);

    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc == 1) {
        return jsInputDeviceMgr->GetKeyboardType(env, id);
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        THROWERR(env, "The second parameter type is wrong");
        return nullptr;
    }
    return jsInputDeviceMgr->GetKeyboardType(env, id, argv[1]);
}

napi_value JsInputDeviceContext::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = {0};
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsInputDeviceContext::CreateEnumKeyboardType(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value none = nullptr;
    CHKRP(env, napi_create_int32(env, KeyboardType::NONE, &none), CREATE_INT32);
    napi_value unknown = nullptr;
    CHKRP(env, napi_create_int32(env, KeyboardType::UNKNOWN, &unknown), CREATE_INT32);
    napi_value alphabeticKeyboard = nullptr;
    CHKRP(env, napi_create_int32(env, KeyboardType::ALPHABETIC_KEYBOARD, &alphabeticKeyboard), CREATE_INT32);
    napi_value digitalKeyboard = nullptr;
    CHKRP(env, napi_create_int32(env, KeyboardType::DIGITAL_KEYBOARD, &digitalKeyboard), CREATE_INT32);
    napi_value handwritingPen = nullptr;
    CHKRP(env, napi_create_int32(env, KeyboardType::HANDWRITING_PEN, &handwritingPen), CREATE_INT32);
    napi_value remoteControl = nullptr;
    CHKRP(env, napi_create_int32(env, KeyboardType::REMOTE_CONTROL, &remoteControl), CREATE_INT32);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("NONE", none),
        DECLARE_NAPI_STATIC_PROPERTY("UNKNOWN", unknown),
        DECLARE_NAPI_STATIC_PROPERTY("ALPHABETIC_KEYBOARD", alphabeticKeyboard),
        DECLARE_NAPI_STATIC_PROPERTY("DIGITAL_KEYBOARD", digitalKeyboard),
        DECLARE_NAPI_STATIC_PROPERTY("HANDWRITING_PEN", handwritingPen),
        DECLARE_NAPI_STATIC_PROPERTY("REMOTE_CONTROL", remoteControl),
    };
    napi_value result = nullptr;
    CHKRP(env, napi_define_class(env, "KeyboardType", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(env, napi_set_named_property(env, exports, "KeyboardType", result), SET_NAMED_PROPERTY);
    return exports;
}

napi_value JsInputDeviceContext::Export(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    auto instance = CreateInstance(env);
    if (instance == nullptr) {
        THROWERR(env, "failed to create instance");
        return nullptr;
    }
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("on", On),
        DECLARE_NAPI_STATIC_FUNCTION("off", Off),
        DECLARE_NAPI_STATIC_FUNCTION("getDevice", GetDevice),
        DECLARE_NAPI_STATIC_FUNCTION("getDeviceIds", GetDeviceIds),
        DECLARE_NAPI_STATIC_FUNCTION("supportKeys", SupportKeys),
        DECLARE_NAPI_STATIC_FUNCTION("getKeyboardType", GetKeyboardType),
    };
    CHKRP(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc), DEFINE_PROPERTIES);
    if (CreateEnumKeyboardType(env, exports) == nullptr) {
        THROWERR(env, "Failed to create keyboard type enum");
        return nullptr;
    }
    return exports;
}
} // namespace MMI
} // namespace OHOS
