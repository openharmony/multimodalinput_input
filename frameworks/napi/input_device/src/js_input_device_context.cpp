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

#include "js_input_device_context.h"

#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsInputDeviceContext"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t MIN_N_SIZE { 1 };
constexpr uint32_t MAX_N_SIZE { 5 };
constexpr int32_t STANDARD_KEY_REPEAT_DELAY { 500 };
constexpr int32_t MIN_KEY_REPEAT_DELAY { 300 };
constexpr int32_t MAX_KEY_REPEAT_DELAY { 1000 };
constexpr int32_t STANDARD_KEY_REPEAT_RATE { 50 };
constexpr int32_t MIN_KEY_REPEAT_RATE { 36 };
constexpr int32_t MAX_KEY_REPEAT_RATE { 100 };
constexpr int32_t ARGC_NUM { 2 };
constexpr size_t INPUT_PARAMETER { 2 };
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
constexpr int32_t SET_VKEY_AREA_NUMBER_PARAMETERS { 4 };
constexpr int32_t UPDATE_VKEY_MS_NUMBER_PARAMETERS { 1 };
constexpr uint32_t VKEY_MS_ARRAY_MAX_SIZE { 300 };
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
enum class VKeyResult : int32_t {
    FAILED = 0,
    SUCCEED = 1,
};
} // namespace

JsInputDeviceContext::JsInputDeviceContext()
{
    mgr_ = std::make_shared<JsInputDeviceManager>();
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
    CHKRP(napi_get_global(env, &global), GET_GLOBAL);

    constexpr char className[] = "JsInputDeviceContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    napi_status status = napi_define_class(env, className, sizeof(className), JsInputDeviceContext::JsConstructor,
                                           nullptr, sizeof(desc) / sizeof(desc[0]), nullptr, &jsClass);
    CHKRP(status, DEFINE_CLASS);

    status = napi_set_named_property(env, global, "multimodalinput_input_device_class", jsClass);
    CHKRP(status, SET_NAMED_PROPERTY);

    napi_value jsInstance = nullptr;
    CHKRP(napi_new_instance(env, jsClass, 0, nullptr, &jsInstance), NEW_INSTANCE);
    CHKRP(napi_set_named_property(env, global, "multimodal_input_device", jsInstance), SET_NAMED_PROPERTY);

    JsInputDeviceContext *jsContext = nullptr;
    CHKRP(napi_unwrap(env, jsInstance, (void**)&jsContext), UNWRAP);
    CHKPP(jsContext);
    CHKRP(napi_create_reference(env, jsInstance, 1, &(jsContext->contextRef_)), CREATE_REFERENCE);

    uint32_t refCount = 0;
    CHKRP(napi_reference_ref(env, jsContext->contextRef_, &refCount), REFERENCE_REF);
    return jsInstance;
}

napi_value JsInputDeviceContext::JsConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data), GET_CB_INFO);

    JsInputDeviceContext *jsContext = new (std::nothrow) JsInputDeviceContext();
    CHKPP(jsContext);
    napi_status status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void* data, void* hin) {
        MMI_HILOGI("jsvm ends");
        JsInputDeviceContext *context = static_cast<JsInputDeviceContext*>(data);
        delete context;
        context = nullptr;
    }, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsContext;
        MMI_HILOGE("Failed to wrap native instance");
        return nullptr;
    }
    return thisVar;
}

JsInputDeviceContext* JsInputDeviceContext::GetInstance(napi_env env)
{
    CALL_DEBUG_ENTER;
    napi_value global = nullptr;
    CHKRP(napi_get_global(env, &global), GET_GLOBAL);

    bool result = false;
    CHKRP(napi_has_named_property(env, global, "multimodal_input_device", &result), HAS_NAMED_PROPERTY);
    if (!result) {
        MMI_HILOGE("multimodal_input_device was not found");
        return nullptr;
    }

    napi_value object = nullptr;
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    CHKRP(napi_get_named_property(env, global, "multimodal_input_device", &object), GET_NAMED_PROPERTY);
    CHKPP(object);

    JsInputDeviceContext *instance = nullptr;
    CHKRP(napi_unwrap(env, object, (void**)&instance), UNWRAP);
    CHKPP(instance);
    napi_close_handle_scope(env, scope);
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
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("Require two parameters");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_string)) {
        MMI_HILOGE("First parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }

    char eventType[MAX_STRING_LEN] = { 0 };
    size_t ret = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], eventType, MAX_STRING_LEN - 1, &ret), GET_VALUE_STRING_UTF8);
    std::string type = eventType;
    if (type != CHANGED_TYPE) {
        MMI_HILOGE("Type is not change");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "type must be change");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Second parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "listener", "function");
        return nullptr;
    }

    JsInputDeviceContext *jsIds = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsIds);
    auto jsInputDeviceMgr = jsIds->GetJsInputDeviceMgr();
    jsInputDeviceMgr->RegisterDevListener(env, type, argv[1]);
    return nullptr;
}

napi_value JsInputDeviceContext::Off(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("Require two parameters");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_string)) {
        MMI_HILOGE("First parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "type", "string");
        return nullptr;
    }

    char eventType[MAX_STRING_LEN] = { 0 };
    size_t ret = 0;
    CHKRP(napi_get_value_string_utf8(env, argv[0], eventType, MAX_STRING_LEN - 1, &ret), GET_VALUE_STRING_UTF8);
    std::string type = eventType;
    if (type != CHANGED_TYPE) {
        MMI_HILOGE("Type is not change");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "type must be change");
        return nullptr;
    }

    JsInputDeviceContext *jsIds = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsIds);
    auto jsInputDeviceMgr = jsIds->GetJsInputDeviceMgr();
    if (argc == 1) {
        jsInputDeviceMgr->UnregisterDevListener(env, type);
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Second parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "listener", "function");
        return nullptr;
    }
    jsInputDeviceMgr->UnregisterDevListener(env, type, argv[1]);
    return nullptr;
}

napi_value JsInputDeviceContext::GetDeviceIds(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc > 1) {
        THROWERR(env, "too many parameters");
        return nullptr;
    }

    JsInputDeviceContext *jsIds = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsIds);
    auto jsInputDeviceMgr = jsIds->GetJsInputDeviceMgr();
    if (argc < 1) {
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
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > INPUT_PARAMETER) {
        THROWERR(env, "the number of parameters is not as expected");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }
    int32_t id = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &id), GET_VALUE_INT32);
    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc == 1) {
        return jsInputDeviceMgr->GetDevice(env, id);
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        THROWERR(env, "Second parameter type is wrong");
        return nullptr;
    }
    return jsInputDeviceMgr->GetDevice(env, id, argv[1]);
}

napi_value JsInputDeviceContext::SupportKeys(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < INPUT_PARAMETER) {
        MMI_HILOGE("Require three parameters");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }

    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("First parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "deviceId", "number");
        return nullptr;
    }
    int32_t deviceId = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &deviceId), GET_VALUE_INT32);

    if (!JsUtil::TypeOf(env, argv[1], napi_object)) {
        MMI_HILOGE("Second parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "keys", "array");
        return nullptr;
    }
    uint32_t size = 0;
    CHKRP(napi_get_array_length(env, argv[1], &size), GET_ARRAY_LENGTH);
    if (size < MIN_N_SIZE || size > MAX_N_SIZE) {
        MMI_HILOGE("Size range error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "size range error");
        return nullptr;
    }

    int32_t data = 0;
    std::vector<int32_t> keyCodes;
    for (uint32_t i = 0; i < size; ++i) {
        napi_value keyValue = nullptr;
        CHKRP(napi_get_element(env, argv[1], i, &keyValue), GET_ELEMENT);
        if (!JsUtil::TypeOf(env, keyValue, napi_number)) {
            MMI_HILOGE("Second parameter type error");
            THROWERR_API9(env, COMMON_PARAMETER_ERROR, "KeyCode", "number");
            return nullptr;
        }
        CHKRP(napi_get_value_int32(env, keyValue, &data), GET_VALUE_INT32);
        keyCodes.push_back(data);
    }

    JsInputDeviceContext *jsContext = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsContext);
    auto jsInputDeviceMgr = jsContext->GetJsInputDeviceMgr();
    if (argc == INPUT_PARAMETER) {
        return jsInputDeviceMgr->SupportKeys(env, deviceId, keyCodes);
    }
    if (!JsUtil::TypeOf(env, argv[2], napi_function)) {
        MMI_HILOGE("Third parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->SupportKeys(env, deviceId, keyCodes, argv[2]);
}

napi_value JsInputDeviceContext::SupportKeysSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = ARGC_NUM;
    napi_value argv[ARGC_NUM] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc != ARGC_NUM) {
        MMI_HILOGE("Require two parameters");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }

    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("First parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "deviceId", "number");
        return nullptr;
    }
    int32_t deviceId = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &deviceId), GET_VALUE_INT32);

    if (!JsUtil::TypeOf(env, argv[1], napi_object)) {
        MMI_HILOGE("Second parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "keys", "array");
        return nullptr;
    }
    uint32_t size = 0;
    CHKRP(napi_get_array_length(env, argv[1], &size), GET_ARRAY_LENGTH);
    if (size < MIN_N_SIZE || size > MAX_N_SIZE) {
        MMI_HILOGE("Size range error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "size range error");
        return nullptr;
    }

    int32_t data = 0;
    std::vector<int32_t> keyCodes;
    for (uint32_t i = 0; i < size; ++i) {
        napi_value keyValue = nullptr;
        CHKRP(napi_get_element(env, argv[1], i, &keyValue), GET_ELEMENT);
        if (!JsUtil::TypeOf(env, keyValue, napi_number)) {
            MMI_HILOGE("Second parameter type error");
            THROWERR_API9(env, COMMON_PARAMETER_ERROR, "KeyCode", "number");
            return nullptr;
        }
        CHKRP(napi_get_value_int32(env, keyValue, &data), GET_VALUE_INT32);
        keyCodes.push_back(data);
    }

    JsInputDeviceContext *jsContext = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsContext);
    auto jsInputDeviceMgr = jsContext->GetJsInputDeviceMgr();
    CHKPP(jsInputDeviceMgr);
    return jsInputDeviceMgr->SupportKeysSync(env, deviceId, keyCodes);
}

napi_value JsInputDeviceContext::GetKeyboardType(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("Require two parameters");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }

    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("First parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "deviceId", "number");
        return nullptr;
    }
    int32_t id = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &id), GET_VALUE_INT32);

    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    CHKPP(jsInputDeviceMgr);
    if (argc == 1) {
        return jsInputDeviceMgr->GetKeyboardType(env, id);
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Second parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->GetKeyboardType(env, id, argv[1]);
}

napi_value JsInputDeviceContext::GetKeyboardTypeSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc != 1) {
        MMI_HILOGE("Require one parameters");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }

    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("First parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "deviceId", "number");
        return nullptr;
    }
    int32_t id = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &id), GET_VALUE_INT32);

    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    CHKPP(jsInputDeviceMgr);

    return jsInputDeviceMgr->GetKeyboardTypeSync(env, id);
}

napi_value JsInputDeviceContext::GetDeviceList(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    JsInputDeviceContext *jsIds = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsIds);
    auto jsInputDeviceMgr = jsIds->GetJsInputDeviceMgr();
    if (argc < 1) {
        return jsInputDeviceMgr->GetDeviceList(env);
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("First parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->GetDeviceList(env, argv[0]);
}

napi_value JsInputDeviceContext::GetDeviceInfo(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("Require two parameters");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("First parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "deviceId", "number");
        return nullptr;
    }
    int32_t id = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &id), GET_VALUE_INT32);

    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc == 1) {
        return jsInputDeviceMgr->GetDeviceInfo(env, id);
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Second parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->GetDeviceInfo(env, id, argv[1]);
}

napi_value JsInputDeviceContext::GetDeviceInfoSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc != 1) {
        MMI_HILOGE("Require one parameters");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("First parameter type error");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "deviceId", "number");
        return nullptr;
    }
    int32_t id = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &id), GET_VALUE_INT32);

    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();

    return jsInputDeviceMgr->GetDeviceInfoSync(env, id);
}

napi_value JsInputDeviceContext::SetKeyboardRepeatDelay(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("delay parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "delay", "number");
        return nullptr;
    }
    int32_t repeatDelay = STANDARD_KEY_REPEAT_DELAY;
    CHKRP(napi_get_value_int32(env, argv[0], &repeatDelay), GET_VALUE_INT32);
    if (repeatDelay < MIN_KEY_REPEAT_DELAY) {
        repeatDelay = MIN_KEY_REPEAT_DELAY;
    } else if (repeatDelay > MAX_KEY_REPEAT_DELAY) {
        repeatDelay = MAX_KEY_REPEAT_DELAY;
    }
    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc == 1) {
        return jsInputDeviceMgr->SetKeyboardRepeatDelay(env, repeatDelay);
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->SetKeyboardRepeatDelay(env, repeatDelay, argv[1]);
}

napi_value JsInputDeviceContext::SetKeyboardRepeatRate(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return nullptr;
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("rate parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "rate", "number");
        return nullptr;
    }
    int32_t repeatRate = STANDARD_KEY_REPEAT_RATE;
    CHKRP(napi_get_value_int32(env, argv[0], &repeatRate), GET_VALUE_INT32);
    if (repeatRate < MIN_KEY_REPEAT_RATE) {
        repeatRate = MIN_KEY_REPEAT_RATE;
    } else if (repeatRate > MAX_KEY_REPEAT_RATE) {
        repeatRate = MAX_KEY_REPEAT_RATE;
    }
    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc == 1) {
        return jsInputDeviceMgr->SetKeyboardRepeatRate(env, repeatRate);
    }
    if (!JsUtil::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->SetKeyboardRepeatRate(env, repeatRate, argv[1]);
}

napi_value JsInputDeviceContext::GetKeyboardRepeatDelay(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc < 1) {
        return jsInputDeviceMgr->GetKeyboardRepeatDelay(env);
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->GetKeyboardRepeatDelay(env, argv[0]);
}

napi_value JsInputDeviceContext::GetKeyboardRepeatRate(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    if (argc < 1) {
        return jsInputDeviceMgr->GetKeyboardRepeatRate(env);
    }
    if (!JsUtil::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsInputDeviceMgr->GetKeyboardRepeatRate(env, argv[0]);
}

napi_value JsInputDeviceContext::GetIntervalSinceLastInput(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsInputDeviceContext *jsDev = JsInputDeviceContext::GetInstance(env);
    CHKPP(jsDev);
    auto jsInputDeviceMgr = jsDev->GetJsInputDeviceMgr();
    return jsInputDeviceMgr->GetIntervalSinceLastInput(env);
}

napi_value JsInputDeviceContext::SetVKeyboardArea(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    size_t argc = SET_VKEY_AREA_NUMBER_PARAMETERS;
    napi_value argv[SET_VKEY_AREA_NUMBER_PARAMETERS] = { nullptr };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc != SET_VKEY_AREA_NUMBER_PARAMETERS) {
        MMI_HILOGE("SetVKeyboardArea parameter number error");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Parameter count error");
        return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
    }
    double topLeftX = 0.0;
    if (!JsUtil::ParseDouble(env, argv[0], topLeftX)) {
        MMI_HILOGE("ParseDouble failed. property name: topLeftX");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "topLeftX", "number");
        return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
    }
    double topLeftY = 0.0;
    if (!JsUtil::ParseDouble(env, argv[1], topLeftY)) {
        MMI_HILOGE("ParseDouble failed. property name: topLeftY");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "topLeftY", "number");
        return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
    }
    double bottomRightX = 0.0;
    if (!JsUtil::ParseDouble(env, argv[2], bottomRightX)) {
        MMI_HILOGE("ParseDouble failed. property name: bottomRightX");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "bottomRightX", "number");
        return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
    }
    double bottomRightY = 0.0;
    if (!JsUtil::ParseDouble(env, argv[3], bottomRightY)) {
        MMI_HILOGE("ParseDouble failed. property name: bottomRightY");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "bottomRightY", "number");
        return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
    }
    int32_t ret = InputManager::GetInstance()->SetVKeyboardArea(topLeftX, topLeftY, bottomRightX, bottomRightY);
    if (ret != RET_OK) {
        MMI_HILOGE("SetVKeyboardArea failed with ret: %{public}d", ret);
        return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
    }
    return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::SUCCEED));
#else
    THROWERR_API9(env, COMMON_CAPABILITY_NOT_SUPPORTED, "SetVKeyboardArea", "Not support");
    return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
}

#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
bool JsInputDeviceContext::ParseBMSArray(napi_env env, napi_value value,
    std::vector<std::shared_ptr<ButtonMotionSpace>>& bmsArray)
{
    uint32_t length = 0;
    if (!JsUtil::IsArray(env, value)) {
        MMI_HILOGE("ParseBMSArray first parameter is not array");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "ButtonMotionSpace", "array");
        bmsArray.clear();
        return false;
    }
    napi_get_array_length(env, value, &length);
    if (length > VKEY_MS_ARRAY_MAX_SIZE) {
        MMI_HILOGE("ParseBMSArray the size of array is larger than maximum size");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "size of motion space", "must be less than or equal 300");
        bmsArray.clear();
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value resBms = nullptr;
        if (napi_get_element(env, value, i, &resBms) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_element failed. index:%{public}d", i);
            bmsArray.clear();
            return false;
        }

        auto bms = std::make_shared<ButtonMotionSpace>();
        if (bms == nullptr) {
            MMI_HILOGE("ParseBMSArray create button motion space failed");
            bmsArray.clear();
            return false;
        }

        napi_value resKeyName = nullptr;
        if (napi_get_named_property(env, resBms, "keyName", &resKeyName) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_named_property failed. property name: keyName");
            bmsArray.clear();
            return false;
        }
        char keyName[MAX_STRING_LEN] = { 0 };
        if (!JsUtil::ParseString(env, resKeyName, keyName)) {
            MMI_HILOGE("ParseBMSArray ParseSeting failed. property name: keyName");
            bmsArray.clear();
            return false;
        }
        bms->keyName = std::string(keyName);

        napi_value resKeyCode = nullptr;
        if (napi_get_named_property(env, resBms, "keyCode", &resKeyCode) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_named_property failed. property name: keyCode");
            bmsArray.clear();
            return false;
        }
        int32_t keyCode = 0;
        if (!JsUtil::ParseInt32(env, resKeyCode, keyCode)) {
            MMI_HILOGE("ParseBMSArray ParseInt32 failed. property name: keyCode");
            bmsArray.clear();
            return false;
        }
        bms->keyCode = keyCode;

        napi_value resLocX = nullptr;
        if (napi_get_named_property(env, resBms, "locX", &resLocX) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_named_property failed. property name: locX");
            bmsArray.clear();
            return false;
        }
        double locX = 0.0;
        if (!JsUtil::ParseDouble(env, resLocX, locX)) {
            MMI_HILOGE("ParseBMSArray ParseDouble failed. property name: locX");
            bmsArray.clear();
            return false;
        }
        bms->locX = locX;

        napi_value resLocY = nullptr;
        if (napi_get_named_property(env, resBms, "locY", &resLocY) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_named_property failed. property name: locY");
            bmsArray.clear();
            return false;
        }
        double locY = 0.0;
        if (!JsUtil::ParseDouble(env, resLocY, locY)) {
            MMI_HILOGE("ParseBMSArray ParseDouble failed. property name: locY");
            bmsArray.clear();
            return false;
        }
        bms->locY = locY;

        napi_value resWidth = nullptr;
        if (napi_get_named_property(env, resBms, "width", &resWidth) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_named_property failed. property name: width");
            bmsArray.clear();
            return false;
        }
        double width = 0.0;
        if (!JsUtil::ParseDouble(env, resWidth, width)) {
            MMI_HILOGE("ParseBMSArray ParseDouble failed. property name: width");
            bmsArray.clear();
            return false;
        }
        bms->width = width;

        napi_value resHeight = nullptr;
        if (napi_get_named_property(env, resBms, "height", &resHeight) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_named_property failed. property name: height");
            bmsArray.clear();
            return false;
        }
        double height = 0.0;
        if (!JsUtil::ParseDouble(env, resHeight, height)) {
            MMI_HILOGE("ParseBMSArray ParseDouble failed. property name: height");
            bmsArray.clear();
            return false;
        }
        bms->height = height;

        napi_value resUseShift = nullptr;
        if (napi_get_named_property(env, resBms, "useShift", &resUseShift) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_named_property failed. property name: useShift");
            bmsArray.clear();
            return false;
        }
        bool useShift = false;
        if (!JsUtil::ParseBool(env, resUseShift, useShift)) {
            MMI_HILOGE("ParseBMSArray ParseBool failed. property name: useShift");
            bmsArray.clear();
            return false;
        }
        bms->useShift = useShift;

        napi_value resMotionSpaceTypeId = nullptr;
        if (napi_get_named_property(env, resBms, "motionSpaceTypeId", &resMotionSpaceTypeId) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_named_property failed. property name: motionSpaceTypeId");
            bmsArray.clear();
            return false;
        }
        int32_t motionSpaceTypeId = 0;
        if (!JsUtil::ParseInt32(env, resMotionSpaceTypeId, motionSpaceTypeId)) {
            MMI_HILOGE("ParseBMSArray ParseInt32 failed. property name: motionSpaceTypeId");
            bmsArray.clear();
            return false;
        }
        bms->motionSpaceTypeId = static_cast<MotionSpaceType>(motionSpaceTypeId);

        napi_value resPageTypeId = nullptr;
        if (napi_get_named_property(env, resBms, "pageTypeId", &resPageTypeId) != napi_ok) {
            MMI_HILOGE("ParseBMSArray napi_get_named_property failed. property name: pageTypeId");
            bmsArray.clear();
            return false;
        }
        int32_t pageTypeId = 0;
        if (!JsUtil::ParseInt32(env, resPageTypeId, pageTypeId)) {
            MMI_HILOGE("ParseBMSArray ParseInt32 failed. property name: pageTypeId");
            bmsArray.clear();
            return false;
        }
        bms->pageTypeId = static_cast<PageType>(pageTypeId);

        bmsArray.push_back(bms);
    }
    return true;
}
#endif // OHOS_BUILD_ENABLE_VKEYBOARD

napi_value JsInputDeviceContext::UpdateMotionSpace(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    size_t argc = UPDATE_VKEY_MS_NUMBER_PARAMETERS;
    napi_value argv[UPDATE_VKEY_MS_NUMBER_PARAMETERS] = { nullptr };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < UPDATE_VKEY_MS_NUMBER_PARAMETERS) {
        MMI_HILOGE("UpdateMotionSpace parameter number error");
        return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
    }
    std::vector<std::shared_ptr<ButtonMotionSpace>> bmsArray;
    if (!ParseBMSArray(env, argv[0], bmsArray)) {
        MMI_HILOGE("ParseBMSArray parse ButtonMotionSpace array fail");
        return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
    } else {
        int32_t ret = RET_OK;
        for (auto item : bmsArray) {
            if (item == nullptr) {
                return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
            }
            std::vector<int32_t> pattern;
            pattern.push_back(static_cast<int32_t>(item->locX));
            pattern.push_back(static_cast<int32_t>(item->locY));
            pattern.push_back(static_cast<int32_t>(item->width));
            pattern.push_back(static_cast<int32_t>(item->height));
            pattern.push_back(item->keyCode);
            pattern.push_back(static_cast<int32_t>(item->motionSpaceTypeId));
            pattern.push_back(static_cast<int32_t>(item->pageTypeId));
            ret = InputManager::GetInstance()->SetMotionSpace(item->keyName, item->useShift, pattern);
            if (ret != RET_OK) {
                MMI_HILOGE("UpdateMotionSpace failed with ret: %{public}d", ret);
                return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
            }
        }
        return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::SUCCEED));
    }
#else
    THROWERR_API9(env, COMMON_CAPABILITY_NOT_SUPPORTED, "UpdateMotionSpace", "Not support");
    return JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED));
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
}

napi_value JsInputDeviceContext::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsInputDeviceContext::CreateEnumKeyboardType(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value none = nullptr;
    CHKRP(napi_create_int32(env, KeyboardType::KEYBOARD_TYPE_NONE, &none), CREATE_INT32);
    napi_value unknown = nullptr;
    CHKRP(napi_create_int32(env, KeyboardType::KEYBOARD_TYPE_UNKNOWN, &unknown), CREATE_INT32);
    napi_value alphabeticKeyboard = nullptr;
    CHKRP(napi_create_int32(env, KeyboardType::KEYBOARD_TYPE_ALPHABETICKEYBOARD, &alphabeticKeyboard), CREATE_INT32);
    napi_value digitalKeyboard = nullptr;
    CHKRP(napi_create_int32(env, KeyboardType::KEYBOARD_TYPE_DIGITALKEYBOARD, &digitalKeyboard), CREATE_INT32);
    napi_value handwritingPen = nullptr;
    CHKRP(napi_create_int32(env, KeyboardType::KEYBOARD_TYPE_HANDWRITINGPEN, &handwritingPen), CREATE_INT32);
    napi_value remoteControl = nullptr;
    CHKRP(napi_create_int32(env, KeyboardType::KEYBOARD_TYPE_REMOTECONTROL, &remoteControl), CREATE_INT32);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("NONE", none),
        DECLARE_NAPI_STATIC_PROPERTY("UNKNOWN", unknown),
        DECLARE_NAPI_STATIC_PROPERTY("ALPHABETIC_KEYBOARD", alphabeticKeyboard),
        DECLARE_NAPI_STATIC_PROPERTY("DIGITAL_KEYBOARD", digitalKeyboard),
        DECLARE_NAPI_STATIC_PROPERTY("HANDWRITING_PEN", handwritingPen),
        DECLARE_NAPI_STATIC_PROPERTY("REMOTE_CONTROL", remoteControl),
    };
    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "KeyboardType", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "KeyboardType", result), SET_NAMED_PROPERTY);
    return exports;
}

napi_value JsInputDeviceContext::CreateEnumVKeyResult(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("FAILED", JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::FAILED))),
        DECLARE_NAPI_STATIC_PROPERTY("SUCCEED", JsUtil::GetNapiInt32(env, static_cast<int32_t>(VKeyResult::SUCCEED))),
    };

    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "VKeyResult", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "VKeyResult", result), SET_NAMED_PROPERTY);
    return exports;
}

napi_value JsInputDeviceContext::CreateEnumMotionSpaceType(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("NARROW",
            JsUtil::GetNapiInt32(env, static_cast<int32_t>(MotionSpaceType::NARROW))),
        DECLARE_NAPI_STATIC_PROPERTY("WIDE",
            JsUtil::GetNapiInt32(env, static_cast<int32_t>(MotionSpaceType::WIDE))),
        DECLARE_NAPI_STATIC_PROPERTY("FLOATING",
            JsUtil::GetNapiInt32(env, static_cast<int32_t>(MotionSpaceType::FLOATING))),
        DECLARE_NAPI_STATIC_PROPERTY("TRACKPAD",
            JsUtil::GetNapiInt32(env, static_cast<int32_t>(MotionSpaceType::TRACKPAD))),
        DECLARE_NAPI_STATIC_PROPERTY("OTHERS",
            JsUtil::GetNapiInt32(env, static_cast<int32_t>(MotionSpaceType::OTHERS))),
    };

    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "MotionSpaceType", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "MotionSpaceType", result), SET_NAMED_PROPERTY);
    return exports;
}

napi_value JsInputDeviceContext::CreateEnumPageType(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("FIRST_PAGE",
            JsUtil::GetNapiInt32(env, static_cast<int32_t>(PageType::FIRST_PAGE))),
        DECLARE_NAPI_STATIC_PROPERTY("SECOND_PAGE_CN",
            JsUtil::GetNapiInt32(env, static_cast<int32_t>(PageType::SECOND_PAGE_CN))),
        DECLARE_NAPI_STATIC_PROPERTY("SECOND_PAGE_EN",
            JsUtil::GetNapiInt32(env, static_cast<int32_t>(PageType::SECOND_PAGE_EN))),
        DECLARE_NAPI_STATIC_PROPERTY("OTHERS", JsUtil::GetNapiInt32(env, static_cast<int32_t>(PageType::OTHERS))),
    };

    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "PageType", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "PageType", result), SET_NAMED_PROPERTY);
    return exports;
}

napi_value JsInputDeviceContext::Export(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    CHKPP(CreateInstance(env));
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("on", On),
        DECLARE_NAPI_STATIC_FUNCTION("off", Off),
        DECLARE_NAPI_STATIC_FUNCTION("getDevice", GetDevice),
        DECLARE_NAPI_STATIC_FUNCTION("getDeviceIds", GetDeviceIds),
        DECLARE_NAPI_STATIC_FUNCTION("supportKeys", SupportKeys),
        DECLARE_NAPI_STATIC_FUNCTION("supportKeysSync", SupportKeysSync),
        DECLARE_NAPI_STATIC_FUNCTION("getKeyboardType", GetKeyboardType),
        DECLARE_NAPI_STATIC_FUNCTION("getKeyboardTypeSync", GetKeyboardTypeSync),
        DECLARE_NAPI_STATIC_FUNCTION("getDeviceList", GetDeviceList),
        DECLARE_NAPI_STATIC_FUNCTION("getDeviceInfo", GetDeviceInfo),
        DECLARE_NAPI_STATIC_FUNCTION("getDeviceInfoSync", GetDeviceInfoSync),
        DECLARE_NAPI_STATIC_FUNCTION("setKeyboardRepeatDelay", SetKeyboardRepeatDelay),
        DECLARE_NAPI_STATIC_FUNCTION("setKeyboardRepeatRate", SetKeyboardRepeatRate),
        DECLARE_NAPI_STATIC_FUNCTION("getKeyboardRepeatDelay", GetKeyboardRepeatDelay),
        DECLARE_NAPI_STATIC_FUNCTION("getKeyboardRepeatRate", GetKeyboardRepeatRate),
        DECLARE_NAPI_STATIC_FUNCTION("getIntervalSinceLastInput", GetIntervalSinceLastInput),
        DECLARE_NAPI_STATIC_FUNCTION("setVKeyboardArea", SetVKeyboardArea),
        DECLARE_NAPI_STATIC_FUNCTION("updateMotionSpace", UpdateMotionSpace),
    };
    CHKRP(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc), DEFINE_PROPERTIES);
    CHKPP(CreateEnumKeyboardType(env, exports));
    CHKPP(CreateEnumVKeyResult(env, exports));
    CHKPP(CreateEnumMotionSpaceType(env, exports));
    CHKPP(CreateEnumPageType(env, exports));
    return exports;
}
} // namespace MMI
} // namespace OHOS
