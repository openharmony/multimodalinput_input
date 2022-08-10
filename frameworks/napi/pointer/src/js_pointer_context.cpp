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

#include "js_pointer_context.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsPointerContext" };
constexpr int32_t STANDARD_SPEED = 5;
constexpr int32_t MAX_SPEED = 10;
constexpr int32_t MIN_SPEED = 1;
} // namespace

JsPointerContext::JsPointerContext() : mgr_(std::make_shared<JsPointerManager>()) {}

napi_value JsPointerContext::CreateInstance(napi_env env)
{
    CALL_DEBUG_ENTER;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), GET_GLOBAL);

    constexpr char className[] = "JsPointerContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    napi_status status = napi_define_class(env, className, sizeof(className), JsPointerContext::CreateJsObject,
                                           nullptr, sizeof(desc) / sizeof(desc[0]), nullptr, &jsClass);
    CHKRP(env, status, DEFINE_CLASS);

    status = napi_set_named_property(env, global, "multimodalinput_pointer_class", jsClass);
    CHKRP(env, status, SET_NAMED_PROPERTY);

    napi_value jsInstance = nullptr;
    CHKRP(env, napi_new_instance(env, jsClass, 0, nullptr, &jsInstance), NEW_INSTANCE);
    CHKRP(env, napi_set_named_property(env, global, "multimodal_pointer", jsInstance), SET_NAMED_PROPERTY);

    JsPointerContext *jsContext = nullptr;
    CHKRP(env, napi_unwrap(env, jsInstance, (void**)&jsContext), UNWRAP);
    CHKPP(jsContext);
    CHKRP(env, napi_create_reference(env, jsInstance, 1, &(jsContext->contextRef_)), CREATE_REFERENCE);

    uint32_t refCount = 0;
    CHKRP(env, napi_reference_ref(env, jsContext->contextRef_, &refCount), REFERENCE_REF);
    return jsInstance;
}

napi_value JsPointerContext::CreateJsObject(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    CHKRP(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data), GET_CB_INFO);

    JsPointerContext *jsContext = new (std::nothrow) JsPointerContext();
    CHKPP(jsContext);
    napi_status status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void* data, void* hin) {
        MMI_HILOGI("jsvm ends");
        JsPointerContext *context = static_cast<JsPointerContext*>(data);
        delete context;
    }, nullptr, nullptr);
    if (status != napi_ok) {
        delete jsContext;
        THROWERR(env, "Failed to wrap native instance");
        return nullptr;
    }
    return thisVar;
}

JsPointerContext* JsPointerContext::GetInstance(napi_env env)
{
    CALL_DEBUG_ENTER;
    napi_value global = nullptr;
    CHKRP(env, napi_get_global(env, &global), GET_GLOBAL);

    bool result = false;
    CHKRP(env, napi_has_named_property(env, global, "multimodal_pointer", &result), HAS_NAMED_PROPERTY);
    if (!result) {
        THROWERR(env, "multimodal_pointer was not found");
        return nullptr;
    }

    napi_value object = nullptr;
    CHKRP(env, napi_get_named_property(env, global, "multimodal_pointer", &object), SET_NAMED_PROPERTY);
    if (object == nullptr) {
        THROWERR(env, "object is nullptr");
        return nullptr;
    }

    JsPointerContext *instance = nullptr;
    CHKRP(env, napi_unwrap(env, object, (void**)&instance), UNWRAP);
    if (instance == nullptr) {
        THROWERR(env, "instance is nullptr");
        return nullptr;
    }
    return instance;
}

std::shared_ptr<JsPointerManager> JsPointerContext::GetJsPointerMgr() const
{
    return mgr_;
}

napi_value JsPointerContext::SetPointerVisible(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > 2) {
        THROWERR(env, "the number of parameters is not as expected");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_boolean)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }
    bool visible = true;
    CHKRP(env, napi_get_value_bool(env, argv[0], &visible), GET_BOOL);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetPointerVisible(env, visible);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        THROWERR(env, "The second parameter type is wrong");
        return nullptr;
    }
    return jsPointerMgr->SetPointerVisible(env, visible, argv[1]);
}

napi_value JsPointerContext::IsPointerVisible(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc > 1) {
        THROWERR(env, "the number of parameters is not as expected");
        return nullptr;
    }

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 0) {
        return jsPointerMgr->IsPointerVisible(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }

    return jsPointerMgr->IsPointerVisible(env, argv[0]);
}

napi_value JsPointerContext::SetPointerSpeed(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > 2) {
        THROWERR(env, "The number of parameters is not as expected");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }
    int32_t pointerSpeed = STANDARD_SPEED;
    CHKRP(env, napi_get_value_int32(env, argv[0], &pointerSpeed), GET_INT32);
    if (pointerSpeed < MIN_SPEED) {
        pointerSpeed = MIN_SPEED;
    } else if (pointerSpeed > MAX_SPEED) {
        pointerSpeed = MAX_SPEED;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetPointerSpeed(env, pointerSpeed);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        THROWERR(env, "The second parameter type is wrong");
        return nullptr;
    }
    return jsPointerMgr->SetPointerSpeed(env, pointerSpeed, argv[1]);
}

napi_value JsPointerContext::GetPointerSpeed(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc > 1) {
        THROWERR(env, "The number of parameters is not as expected");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 0) {
        return jsPointerMgr->GetPointerSpeed(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }

    return jsPointerMgr->GetPointerSpeed(env, argv[0]);
}

napi_value JsPointerContext::Export(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    auto instance = CreateInstance(env);
    if (instance == nullptr) {
        THROWERR(env, "failed to create instance");
        return nullptr;
    }
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_FUNCTION("setPointerVisible", SetPointerVisible),
        DECLARE_NAPI_STATIC_FUNCTION("isPointerVisible", IsPointerVisible),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerSpeed", SetPointerSpeed),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerSpeed", GetPointerSpeed),
    };
    CHKRP(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc), DEFINE_PROPERTIES);
    return exports;
}

napi_value JsPointerContext::SetPointerLocation(napi_env env, napi_callback_info info)
{
    CALL_INFO_TRACE;
    size_t argc = 3;
    napi_value argv[3];
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc > 3 || argc < 2) {
        THROWERR(env, "the number of parameters is not as expected");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "The first parameter type is wrong");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_number)) {
        THROWERR(env, "The second parameter type is wrong");
        return nullptr;
    }
    int32_t x = 0;
    int32_t y = 0;
    CHKRP(env, napi_get_value_int32(env, argv[0], &x), GET_INT32);
    CHKRP(env, napi_get_value_int32(env, argv[1], &y), GET_INT32);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 2) {
        return jsPointerMgr->SetPointerLocation(env, nullptr, x, y);
    }
    if (!JsCommon::TypeOf(env, argv[2], napi_function)) {
        THROWERR(env, "The third parameter type is wrong");
        return nullptr;
    }
    return jsPointerMgr->SetPointerLocation(env, argv[2], x, y);
}
} // namespace MMI
} // namespace OHOS
