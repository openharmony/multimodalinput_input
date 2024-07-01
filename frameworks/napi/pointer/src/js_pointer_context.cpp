/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_pointer_context.h"
#include "pixel_map.h"
#include "pixel_map_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsPointerContext"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t STANDARD_SPEED { 5 };
constexpr int32_t MAX_SPEED { 11 };
constexpr int32_t MIN_SPEED { 1 };
constexpr int32_t DEFAULT_ROWS { 3 };
constexpr int32_t MIN_ROWS { 1 };
constexpr int32_t MAX_ROWS { 100 };
constexpr size_t INPUT_PARAMETER { 2 };
constexpr int32_t DEFAULT_POINTER_SIZE { 1 };
constexpr int32_t MIN_POINTER_SIZE { 1 };
constexpr int32_t MAX_POINTER_SIZE { 7 };
constexpr int32_t MIN_POINTER_COLOR { 0x000000 };
constexpr int32_t THREE_PARAMETERS { 3 };
constexpr int32_t INVALID_VALUE { -2 };
} // namespace

JsPointerContext::JsPointerContext() : mgr_(std::make_shared<JsPointerManager>()) {}

napi_value JsPointerContext::CreateInstance(napi_env env)
{
    CALL_DEBUG_ENTER;
    napi_value global = nullptr;
    CHKRP(napi_get_global(env, &global), GET_GLOBAL);

    constexpr char className[] = "JsPointerContext";
    napi_value jsClass = nullptr;
    napi_property_descriptor desc[] = {};
    napi_status status = napi_define_class(env, className, sizeof(className), JsPointerContext::CreateJsObject,
                                           nullptr, sizeof(desc) / sizeof(desc[0]), nullptr, &jsClass);
    CHKRP(status, DEFINE_CLASS);

    status = napi_set_named_property(env, global, "multimodalinput_pointer_class", jsClass);
    CHKRP(status, SET_NAMED_PROPERTY);

    napi_value jsInstance = nullptr;
    CHKRP(napi_new_instance(env, jsClass, 0, nullptr, &jsInstance), NEW_INSTANCE);
    CHKRP(napi_set_named_property(env, global, "multimodal_pointer", jsInstance), SET_NAMED_PROPERTY);

    JsPointerContext *jsContext = nullptr;
    CHKRP(napi_unwrap(env, jsInstance, (void**)&jsContext), UNWRAP);
    CHKPP(jsContext);
    CHKRP(napi_create_reference(env, jsInstance, 1, &(jsContext->contextRef_)), CREATE_REFERENCE);

    uint32_t refCount = 0;
    CHKRP(napi_reference_ref(env, jsContext->contextRef_, &refCount), REFERENCE_REF);
    return jsInstance;
}

napi_value JsPointerContext::CreateJsObject(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    napi_value thisVar = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, &data), GET_CB_INFO);

    JsPointerContext *jsContext = new (std::nothrow) JsPointerContext();
    CHKPP(jsContext);
    napi_status status = napi_wrap(env, thisVar, jsContext, [](napi_env env, void* data, void* hin) {
        MMI_HILOGI("Jsvm ends");
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
    CHKRP(napi_get_global(env, &global), GET_GLOBAL);

    bool result = false;
    CHKRP(napi_has_named_property(env, global, "multimodal_pointer", &result), HAS_NAMED_PROPERTY);
    if (!result) {
        THROWERR(env, "multimodal_pointer was not found");
        return nullptr;
    }

    napi_value object = nullptr;
    CHKRP(napi_get_named_property(env, global, "multimodal_pointer", &object), SET_NAMED_PROPERTY);
    if (object == nullptr) {
        THROWERR(env, "object is nullptr");
        return nullptr;
    }

    JsPointerContext *instance = nullptr;
    CHKRP(napi_unwrap(env, object, (void**)&instance), UNWRAP);
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
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least one parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "visible", "boolean");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_boolean)) {
        MMI_HILOGE("visible parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "visible", "boolean");
        return nullptr;
    }
    bool visible = true;
    CHKRP(napi_get_value_bool(env, argv[0], &visible), GET_VALUE_BOOL);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetPointerVisible(env, visible);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetPointerVisible(env, visible, argv[1]);
}

napi_value JsPointerContext::SetPointerVisibleSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least one parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "visible", "boolean");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_boolean)) {
        MMI_HILOGE("visible parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "visible", "boolean");
        return nullptr;
    }
    bool visible = true;
    CHKRP(napi_get_value_bool(env, argv[0], &visible), GET_VALUE_BOOL);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->SetPointerVisibleSync(env, visible);
}

napi_value JsPointerContext::IsPointerVisible(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc < 1) {
        return jsPointerMgr->IsPointerVisible(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return jsPointerMgr->IsPointerVisible(env, argv[0]);
}

napi_value JsPointerContext::IsPointerVisibleSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->IsPointerVisibleSync(env);
}

napi_value JsPointerContext::SetPointerColor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "color", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("Color parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "color", "number");
        return nullptr;
    }
    int32_t color = MIN_POINTER_COLOR;
    CHKRP(napi_get_value_int32(env, argv[0], &color), GET_VALUE_INT32);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetPointerColor(env, color);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetPointerColor(env, color, argv[1]);
}

napi_value JsPointerContext::GetPointerColor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc < 1) {
        return jsPointerMgr->GetPointerColor(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return jsPointerMgr->GetPointerColor(env, argv[0]);
}

napi_value JsPointerContext::SetPointerColorSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "color", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("Color parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "color", "number");
        return nullptr;
    }
    int32_t color = MIN_POINTER_COLOR;
    CHKRP(napi_get_value_int32(env, argv[0], &color), GET_VALUE_INT32);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->SetPointerColorSync(env, color);
}

napi_value JsPointerContext::GetPointerColorSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->GetPointerColorSync(env);
}

napi_value JsPointerContext::SetPointerSpeed(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "speed", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("Speed parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "speed", "number");
        return nullptr;
    }
    int32_t pointerSpeed = STANDARD_SPEED;
    CHKRP(napi_get_value_int32(env, argv[0], &pointerSpeed), GET_VALUE_INT32);
    if (pointerSpeed < MIN_SPEED) {
        pointerSpeed = MIN_SPEED;
    } else if (pointerSpeed > MAX_SPEED) {
        pointerSpeed = MAX_SPEED;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetPointerSpeed(env, pointerSpeed);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetPointerSpeed(env, pointerSpeed, argv[1]);
}

napi_value JsPointerContext::SetPointerSpeedSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "speed", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("Speed parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "speed", "number");
        return nullptr;
    }
    int32_t pointerSpeed = STANDARD_SPEED;
    CHKRP(napi_get_value_int32(env, argv[0], &pointerSpeed), GET_VALUE_INT32);
    if (pointerSpeed < MIN_SPEED) {
        pointerSpeed = MIN_SPEED;
    } else if (pointerSpeed > MAX_SPEED) {
        pointerSpeed = MAX_SPEED;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->SetPointerSpeedSync(env, pointerSpeed);
}

napi_value JsPointerContext::GetPointerSpeed(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc < 1) {
        return jsPointerMgr->GetPointerSpeed(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return jsPointerMgr->GetPointerSpeed(env, argv[0]);
}

napi_value JsPointerContext::GetPointerSpeedSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->GetPointerSpeedSync(env);
}

napi_value JsPointerContext::SetMouseScrollRows(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "rows", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("Rows parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "rows", "number");
        return nullptr;
    }
    int32_t rows = DEFAULT_ROWS;
    CHKRP(napi_get_value_int32(env, argv[0], &rows), GET_VALUE_INT32);
    if (rows < MIN_ROWS) {
        rows = MIN_ROWS;
    } else if (rows > MAX_ROWS) {
        rows = MAX_ROWS;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetMouseScrollRows(env, rows);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetMouseScrollRows(env, rows, argv[1]);
}

napi_value JsPointerContext::GetMouseScrollRows(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc < 1) {
        return jsPointerMgr->GetMouseScrollRows(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return jsPointerMgr->GetMouseScrollRows(env, argv[0]);
}

napi_value JsPointerContext::SetPointerLocation(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < INPUT_PARAMETER) {
        MMI_HILOGE("At least 2 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "x", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("x parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "x", "number");
        return nullptr;
    }
    int32_t x = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &x), GET_VALUE_INT32);
    if (x < 0) {
        MMI_HILOGE("Invalid x");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "x is invalid");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_number)) {
        MMI_HILOGE("y parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "y", "number");
        return nullptr;
    }
    int32_t y = 0;
    CHKRP(napi_get_value_int32(env, argv[1], &y), GET_VALUE_INT32);
    if (y < 0) {
        MMI_HILOGE("Invalid y");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "y is invalid");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == INPUT_PARAMETER) {
        return jsPointerMgr->SetPointerLocation(env, x, y);
    }
    if (!JsCommon::TypeOf(env, argv[INPUT_PARAMETER], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetPointerLocation(env, x, y, argv[INPUT_PARAMETER]);
}

napi_value JsPointerContext::SetCustomCursor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 4;
    napi_value argv[4] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < INPUT_PARAMETER) {
        MMI_HILOGE("At least 2 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }

    int32_t windowId = GetWindowId(env, argv[0]);
    if (windowId == INVALID_VALUE) {
        return nullptr;
    }

    if (!JsCommon::TypeOf(env, argv[1], napi_object)) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "pixelMap", "napi_object");
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMapNapi::GetPixelMap(env, argv[1]);
    if (pixelMap == nullptr) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "pixelMap is invalid");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CursorFocus cursorFocus;
    if (argc == INPUT_PARAMETER) {
        return jsPointerMgr->SetCustomCursor(env, windowId, (void *)pixelMap.get(), cursorFocus);
    }

    cursorFocus.x = GetCursorFocusX(env, argv[INPUT_PARAMETER]);
    if (cursorFocus.x == INVALID_VALUE) {
        return nullptr;
    }
    if (argc == THREE_PARAMETERS) {
        return jsPointerMgr->SetCustomCursor(env, windowId, (void *)pixelMap.get(), cursorFocus);
    }

    cursorFocus.y = GetCursorFocusY(env, argv[THREE_PARAMETERS]);
    if (cursorFocus.y == INVALID_VALUE) {
        return nullptr;
    }
    return jsPointerMgr->SetCustomCursor(env, windowId, (void *)pixelMap.get(), cursorFocus);
}

napi_value JsPointerContext::SetCustomCursorSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 4;
    napi_value argv[4] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < INPUT_PARAMETER) {
        MMI_HILOGE("At least 2 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }

    int32_t windowId = GetWindowId(env, argv[0]);
    if (windowId == INVALID_VALUE) {
        return nullptr;
    }

    if (!JsCommon::TypeOf(env, argv[1], napi_object)) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "pixelMap", "napi_object");
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMapNapi::GetPixelMap(env, argv[1]);
    if (pixelMap == nullptr) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "pixelMap is invalid");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CursorFocus cursorFocus;
    if (argc == INPUT_PARAMETER) {
        return jsPointerMgr->SetCustomCursorSync(env, windowId, (void *)pixelMap.get(), cursorFocus);
    }

    cursorFocus.x = GetCursorFocusX(env, argv[INPUT_PARAMETER]);
    if (cursorFocus.x == INVALID_VALUE) {
        return nullptr;
    }
    if (argc == THREE_PARAMETERS) {
        return jsPointerMgr->SetCustomCursorSync(env, windowId, (void *)pixelMap.get(), cursorFocus);
    }

    cursorFocus.y = GetCursorFocusY(env, argv[THREE_PARAMETERS]);
    if (cursorFocus.y == INVALID_VALUE) {
        return nullptr;
    }
    return jsPointerMgr->SetCustomCursorSync(env, windowId, (void *)pixelMap.get(), cursorFocus);
}

int32_t JsPointerContext::GetWindowId(napi_env env, napi_value value)
{
    if (!JsCommon::TypeOf(env, value, napi_number)) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return INVALID_VALUE;
    }
    int32_t windowId = 0;
    CHKRR(napi_get_value_int32(env, value, &windowId), GET_VALUE_INT32, INVALID_VALUE);
    if (windowId < 0 && windowId != GLOBAL_WINDOW_ID) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Windowid is invalid");
        return INVALID_VALUE;
    }
    return windowId;
}

int32_t JsPointerContext::GetCursorFocusX(napi_env env, napi_value value)
{
    if (!JsCommon::TypeOf(env, value, napi_number)) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "focusX", "number");
        return INVALID_VALUE;
    }
    int32_t focusX = 0;
    CHKRR(napi_get_value_int32(env, value, &focusX), GET_VALUE_INT32, INVALID_VALUE);
    if (focusX < 0) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "focusX is invalid");
        return INVALID_VALUE;
    }
    return focusX;
}

int32_t JsPointerContext::GetCursorFocusY(napi_env env, napi_value value)
{
    if (!JsCommon::TypeOf(env, value, napi_number)) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "focusY", "number");
        return INVALID_VALUE;
    }
    int32_t focusY = 0;
    CHKRR(napi_get_value_int32(env, value, &focusY), GET_VALUE_INT32, INVALID_VALUE);
    if (focusY < 0) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "focusY is invalid");
        return INVALID_VALUE;
    }
    return focusY;
}

napi_value JsPointerContext::SetPointerSize(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "size", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("Size parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "size", "number");
        return nullptr;
    }
    int32_t size = DEFAULT_POINTER_SIZE;
    CHKRP(napi_get_value_int32(env, argv[0], &size), GET_VALUE_INT32);
    if (size < MIN_POINTER_SIZE) {
        size = MIN_POINTER_SIZE;
    } else if (size > MAX_POINTER_SIZE) {
        size = MAX_POINTER_SIZE;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetPointerSize(env, size);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetPointerSize(env, size, argv[1]);
}

napi_value JsPointerContext::GetPointerSize(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc < 1) {
        return jsPointerMgr->GetPointerSize(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return jsPointerMgr->GetPointerSize(env, argv[0]);
}

napi_value JsPointerContext::SetPointerSizeSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "size", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("Size parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "size", "number");
        return nullptr;
    }
    int32_t size = DEFAULT_POINTER_SIZE;
    CHKRP(napi_get_value_int32(env, argv[0], &size), GET_VALUE_INT32);
    if (size < MIN_POINTER_SIZE) {
        size = MIN_POINTER_SIZE;
    } else if (size > MAX_POINTER_SIZE) {
        size = MAX_POINTER_SIZE;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->SetPointerSizeSync(env, size);
}

napi_value JsPointerContext::GetPointerSizeSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->GetPointerSizeSync(env);
}

napi_value JsPointerContext::SetPointerStyle(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < INPUT_PARAMETER) {
        MMI_HILOGE("At least 2 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("windowId parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }
    int32_t windowid = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &windowid), GET_VALUE_INT32);
    if (windowid < 0 && windowid != GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowid");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Windowid is invalid");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_number)) {
        MMI_HILOGE("pointerStyle parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "pointerStyle", "number");
        return nullptr;
    }
    int32_t pointerStyle = 0;
    CHKRP(napi_get_value_int32(env, argv[1], &pointerStyle), GET_VALUE_INT32);
    if ((pointerStyle < DEFAULT && pointerStyle != DEVELOPER_DEFINED_ICON) || pointerStyle > RUNNING) {
        MMI_HILOGE("Undefined pointer style");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Pointer style does not exist");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == INPUT_PARAMETER) {
        return jsPointerMgr->SetPointerStyle(env, windowid, pointerStyle);
    }
    if (!JsCommon::TypeOf(env, argv[INPUT_PARAMETER], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetPointerStyle(env, windowid, pointerStyle, argv[INPUT_PARAMETER]);
}

napi_value JsPointerContext::SetPointerStyleSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < INPUT_PARAMETER) {
        MMI_HILOGE("At least 2 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("windowId parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }
    int32_t windowid = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &windowid), GET_VALUE_INT32);
    if (windowid < 0 && windowid != GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowid");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Windowid is invalid");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_number)) {
        MMI_HILOGE("pointerStyle parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "pointerStyle", "number");
        return nullptr;
    }
    int32_t pointerStyle = 0;
    CHKRP(napi_get_value_int32(env, argv[1], &pointerStyle), GET_VALUE_INT32);
    if ((pointerStyle < DEFAULT && pointerStyle != DEVELOPER_DEFINED_ICON) || pointerStyle > RUNNING) {
        MMI_HILOGE("Undefined pointer style");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Pointer style does not exist");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->SetPointerStyleSync(env, windowid, pointerStyle);
}

napi_value JsPointerContext::GetPointerStyle(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("windowId parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }
    int32_t windowid = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &windowid), GET_VALUE_INT32);
    if (windowid < 0 && windowid != GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowid");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Windowid is invalid");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->GetPointerStyle(env, windowid);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->GetPointerStyle(env, windowid, argv[1]);
}

napi_value JsPointerContext::GetPointerStyleSync(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("windowId parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "windowId", "number");
        return nullptr;
    }
    int32_t windowId = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &windowId), GET_VALUE_INT32);
    if (windowId < 0 && windowId != GLOBAL_WINDOW_ID) {
        MMI_HILOGE("Invalid windowId");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "WindowId is invalid");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->GetPointerStyleSync(env, windowId);
}

napi_value JsPointerContext::CreatePointerStyle(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value defaults = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::DEFAULT, &defaults), CREATE_INT32);
    napi_value east = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::EAST, &east), CREATE_INT32);
    napi_value west = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::WEST, &west), CREATE_INT32);
    napi_value south = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::SOUTH, &south), CREATE_INT32);
    napi_value north = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::NORTH, &north), CREATE_INT32);
    napi_value west_east = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::WEST_EAST, &west_east), CREATE_INT32);
    napi_value north_south = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::NORTH_SOUTH, &north_south), CREATE_INT32);
    napi_value north_east = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::NORTH_EAST, &north_east), CREATE_INT32);
    napi_value north_west = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::NORTH_WEST, &north_west), CREATE_INT32);
    napi_value south_east = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::SOUTH_EAST, &south_east), CREATE_INT32);
    napi_value south_west = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::SOUTH_WEST, &south_west), CREATE_INT32);
    napi_value north_east_south_west = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::NORTH_EAST_SOUTH_WEST, &north_east_south_west), CREATE_INT32);
    napi_value north_west_south_east = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::NORTH_WEST_SOUTH_EAST, &north_west_south_east), CREATE_INT32);
    napi_value cross = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::CROSS, &cross), CREATE_INT32);
    napi_value cursor_copy = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::CURSOR_COPY, &cursor_copy), CREATE_INT32);
    napi_value cursor_forbid = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::CURSOR_FORBID, &cursor_forbid), CREATE_INT32);
    napi_value color_sucker = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::COLOR_SUCKER, &color_sucker), CREATE_INT32);
    napi_value hand_grabbing = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::HAND_GRABBING, &hand_grabbing), CREATE_INT32);
    napi_value hand_open = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::HAND_OPEN, &hand_open), CREATE_INT32);
    napi_value hand_pointing = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::HAND_POINTING, &hand_pointing), CREATE_INT32);
    napi_value help = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::HELP, &help), CREATE_INT32);
    napi_value move = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::CURSOR_MOVE, &move), CREATE_INT32);
    napi_value resize_left_right = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::RESIZE_LEFT_RIGHT, &resize_left_right), CREATE_INT32);
    napi_value resize_up_down = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::RESIZE_UP_DOWN, &resize_up_down), CREATE_INT32);
    napi_value screenshot_choose = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::SCREENSHOT_CHOOSE, &screenshot_choose), CREATE_INT32);
    napi_value screenshot_cursor = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::SCREENSHOT_CURSOR, &screenshot_cursor), CREATE_INT32);
    napi_value text_cursor = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::TEXT_CURSOR, &text_cursor), CREATE_INT32);
    napi_value zoom_in = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::ZOOM_IN, &zoom_in), CREATE_INT32);
    napi_value zoom_out = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::ZOOM_OUT, &zoom_out), CREATE_INT32);
    napi_value middle_btn_east = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_EAST, &middle_btn_east), CREATE_INT32);
    napi_value middle_btn_west = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_WEST, &middle_btn_west), CREATE_INT32);
    napi_value middle_btn_south = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_SOUTH, &middle_btn_south), CREATE_INT32);
    napi_value middle_btn_north = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_NORTH, &middle_btn_north), CREATE_INT32);
    napi_value middle_btn_north_south = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_NORTH_SOUTH, &middle_btn_north_south), CREATE_INT32);
    napi_value middle_btn_north_east = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_NORTH_EAST, &middle_btn_north_east), CREATE_INT32);
    napi_value middle_btn_north_west = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_NORTH_WEST, &middle_btn_north_west), CREATE_INT32);
    napi_value middle_btn_south_east = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_SOUTH_EAST, &middle_btn_south_east), CREATE_INT32);
    napi_value middle_btn_south_west = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_SOUTH_WEST, &middle_btn_south_west), CREATE_INT32);
    napi_value middle_btn_north_south_west_east = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::MIDDLE_BTN_NORTH_SOUTH_WEST_EAST,
        &middle_btn_north_south_west_east), CREATE_INT32);
    napi_value horizontal_text_cursor = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::HORIZONTAL_TEXT_CURSOR, &horizontal_text_cursor), CREATE_INT32);
    napi_value cursor_cross = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::CURSOR_CROSS, &cursor_cross), CREATE_INT32);
    napi_value cursor_circle = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::CURSOR_CIRCLE, &cursor_circle), CREATE_INT32);
    napi_value loading = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::LOADING, &loading), CREATE_INT32);
    napi_value running = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::RUNNING, &running), CREATE_INT32);
    napi_value developer_defined_icon = nullptr;
    CHKRP(napi_create_int32(env, MOUSE_ICON::DEVELOPER_DEFINED_ICON, &developer_defined_icon), CREATE_INT32);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("DEFAULT", defaults),
        DECLARE_NAPI_STATIC_PROPERTY("EAST", east),
        DECLARE_NAPI_STATIC_PROPERTY("WEST", west),
        DECLARE_NAPI_STATIC_PROPERTY("SOUTH", south),
        DECLARE_NAPI_STATIC_PROPERTY("NORTH", north),
        DECLARE_NAPI_STATIC_PROPERTY("WEST_EAST", west_east),
        DECLARE_NAPI_STATIC_PROPERTY("NORTH_SOUTH", north_south),
        DECLARE_NAPI_STATIC_PROPERTY("NORTH_EAST", north_east),
        DECLARE_NAPI_STATIC_PROPERTY("NORTH_WEST", north_west),
        DECLARE_NAPI_STATIC_PROPERTY("SOUTH_EAST", south_east),
        DECLARE_NAPI_STATIC_PROPERTY("SOUTH_WEST", south_west),
        DECLARE_NAPI_STATIC_PROPERTY("NORTH_EAST_SOUTH_WEST", north_east_south_west),
        DECLARE_NAPI_STATIC_PROPERTY("NORTH_WEST_SOUTH_EAST", north_west_south_east),
        DECLARE_NAPI_STATIC_PROPERTY("CROSS", cross),
        DECLARE_NAPI_STATIC_PROPERTY("CURSOR_COPY", cursor_copy),
        DECLARE_NAPI_STATIC_PROPERTY("CURSOR_FORBID", cursor_forbid),
        DECLARE_NAPI_STATIC_PROPERTY("COLOR_SUCKER", color_sucker),
        DECLARE_NAPI_STATIC_PROPERTY("HAND_GRABBING", hand_grabbing),
        DECLARE_NAPI_STATIC_PROPERTY("HAND_OPEN", hand_open),
        DECLARE_NAPI_STATIC_PROPERTY("HAND_POINTING", hand_pointing),
        DECLARE_NAPI_STATIC_PROPERTY("HELP", help),
        DECLARE_NAPI_STATIC_PROPERTY("MOVE", move),
        DECLARE_NAPI_STATIC_PROPERTY("RESIZE_LEFT_RIGHT", resize_left_right),
        DECLARE_NAPI_STATIC_PROPERTY("RESIZE_UP_DOWN", resize_up_down),
        DECLARE_NAPI_STATIC_PROPERTY("SCREENSHOT_CHOOSE", screenshot_choose),
        DECLARE_NAPI_STATIC_PROPERTY("SCREENSHOT_CURSOR", screenshot_cursor),
        DECLARE_NAPI_STATIC_PROPERTY("TEXT_CURSOR", text_cursor),
        DECLARE_NAPI_STATIC_PROPERTY("ZOOM_IN", zoom_in),
        DECLARE_NAPI_STATIC_PROPERTY("ZOOM_OUT", zoom_out),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_EAST", middle_btn_east),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_WEST", middle_btn_west),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_SOUTH", middle_btn_south),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_NORTH", middle_btn_north),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_NORTH_SOUTH", middle_btn_north_south),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_NORTH_EAST", middle_btn_north_east),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_NORTH_WEST", middle_btn_north_west),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_SOUTH_EAST", middle_btn_south_east),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_SOUTH_WEST", middle_btn_south_west),
        DECLARE_NAPI_STATIC_PROPERTY("MIDDLE_BTN_NORTH_SOUTH_WEST_EAST", middle_btn_north_south_west_east),
        DECLARE_NAPI_STATIC_PROPERTY("HORIZONTAL_TEXT_CURSOR", horizontal_text_cursor),
        DECLARE_NAPI_STATIC_PROPERTY("CURSOR_CROSS", cursor_cross),
        DECLARE_NAPI_STATIC_PROPERTY("CURSOR_CIRCLE", cursor_circle),
        DECLARE_NAPI_STATIC_PROPERTY("LOADING", loading),
        DECLARE_NAPI_STATIC_PROPERTY("RUNNING", running),
        DECLARE_NAPI_STATIC_PROPERTY("DEVELOPER_DEFINED_ICON", developer_defined_icon),
    };
    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "PointerStyle", NAPI_AUTO_LENGTH, EnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "PointerStyle", result), SET_NAMED_PROPERTY);
    return exports;
}

napi_value JsPointerContext::CreateTouchpadRightClickType(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value touchpad_right_button = nullptr;
    CHKRP(napi_create_int32(env, RightClickType::TOUCHPAD_RIGHT_BUTTON, &touchpad_right_button), CREATE_INT32);
    napi_value touchpad_left_button = nullptr;
    CHKRP(napi_create_int32(env, RightClickType::TOUCHPAD_LEFT_BUTTON, &touchpad_left_button), CREATE_INT32);
    napi_value touchpad_two_finger_tap = nullptr;
    CHKRP(napi_create_int32(env, RightClickType::TOUCHPAD_TWO_FINGER_TAP, &touchpad_two_finger_tap), CREATE_INT32);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("TOUCHPAD_RIGHT_BUTTON", touchpad_right_button),
        DECLARE_NAPI_STATIC_PROPERTY("TOUCHPAD_LEFT_BUTTON", touchpad_left_button),
        DECLARE_NAPI_STATIC_PROPERTY("TOUCHPAD_TWO_FINGER_TAP", touchpad_two_finger_tap),
    };
    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "RightClickType", NAPI_AUTO_LENGTH, EnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "RightClickType", result), SET_NAMED_PROPERTY);
    return exports;
}

napi_value JsPointerContext::EnumConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsPointerContext::EnterCaptureMode(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > INPUT_PARAMETER) {
        THROWERR(env, "The number of parameters is not as expected");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "First parameter type is invalid");
        return nullptr;
    }

    int32_t windowId = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &windowId), GET_VALUE_INT32);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->EnterCaptureMode(env, windowId);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        THROWERR(env, "Second parameter type is invalid");
        return nullptr;
    }
    return jsPointerMgr->EnterCaptureMode(env, windowId, argv[1]);
}

napi_value JsPointerContext::LeaveCaptureMode(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > INPUT_PARAMETER) {
        THROWERR(env, "The number of parameters is not as expected");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "First parameter type is invalid");
        return nullptr;
    }

    int32_t windowId = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &windowId), GET_VALUE_INT32);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->LeaveCaptureMode(env, windowId);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        THROWERR(env, "Second parameter type is invalid");
        return nullptr;
    }
    return jsPointerMgr->LeaveCaptureMode(env, windowId, argv[1]);
}

napi_value JsPointerContext::CreateMousePrimaryButton(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value leftButton = nullptr;
    CHKRP(napi_create_int32(env, PrimaryButton::LEFT_BUTTON, &leftButton), CREATE_INT32);
    napi_value rightButton = nullptr;
    CHKRP(napi_create_int32(env, PrimaryButton::RIGHT_BUTTON, &rightButton), CREATE_INT32);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("LEFT", leftButton),
        DECLARE_NAPI_STATIC_PROPERTY("RIGHT", rightButton),
    };
    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "PrimaryButton", NAPI_AUTO_LENGTH, EnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "PrimaryButton", result), SET_NAMED_PROPERTY);
    return exports;
}

napi_value JsPointerContext::SetMousePrimaryButton(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least one parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "primaryButton", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("primaryButton parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "primaryButton", "number");
        return nullptr;
    }
    int32_t primaryButton = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &primaryButton), GET_VALUE_INT32);
    if (primaryButton < LEFT_BUTTON || primaryButton > RIGHT_BUTTON) {
        MMI_HILOGE("Undefined mouse primary button");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Mouse primary button does not exist");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetMousePrimaryButton(env, primaryButton);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetMousePrimaryButton(env, primaryButton, argv[1]);
}

napi_value JsPointerContext::GetMousePrimaryButton(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc < 1) {
        return jsPointerMgr->GetMousePrimaryButton(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->GetMousePrimaryButton(env, argv[0]);
}

napi_value JsPointerContext::SetHoverScrollState(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least one parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "state", "boolean");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_boolean)) {
        MMI_HILOGE("State parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "state", "boolean");
        return nullptr;
    }
    bool state = true;
    CHKRP(napi_get_value_bool(env, argv[0], &state), GET_VALUE_BOOL);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetHoverScrollState(env, state);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetHoverScrollState(env, state, argv[1]);
}

napi_value JsPointerContext::GetHoverScrollState(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc < 1) {
        return jsPointerMgr->GetHoverScrollState(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->GetHoverScrollState(env, argv[0]);
}

napi_value JsPointerContext::SetTouchpadBoolData(napi_env env, napi_callback_info info, SetTouchpadBoolDataFunc func)
{
    CALL_DEBUG_ENTER;
    if (!func) {
        MMI_HILOGE("func is nullptr");
        return nullptr;
    }
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        MMI_HILOGE("At least one parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "switchFlag", "boolean");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_boolean)) {
        MMI_HILOGE("Bool data parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "switchFlag", "boolean");
        return nullptr;
    }
    bool switchFlag = true;
    CHKRP(napi_get_value_bool(env, argv[0], &switchFlag), GET_VALUE_BOOL);

    if (argc == 1) {
        return func(env, switchFlag, nullptr);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return func(env, switchFlag, argv[1]);
}

napi_value JsPointerContext::SetTouchpadInt32Data(napi_env env, napi_callback_info info, SetTouchpadInt32DataFunc func,
    int32_t dataMax, int32_t dataMin)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 0) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "data", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("Int32 data parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "data", "number");
        return nullptr;
    }
    int32_t data = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &data), GET_VALUE_INT32);
    if (data < dataMin) {
        data = dataMin;
    } else if (data > dataMax) {
        data = dataMax;
    }

    if (argc == 1) {
        return func(env, data, nullptr);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return func(env, data, argv[1]);
}

napi_value JsPointerContext::GetTouchpadData(napi_env env, napi_callback_info info, GetTouchpadFunc func)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    if (argc < 1) {
        return func(env, nullptr);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("Callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return func(env, argv[0]);
}

napi_value JsPointerContext::SetTouchpadScrollSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, bool switchFlag, napi_value handle) -> napi_value {
        return jsPointerMgr->SetTouchpadScrollSwitch(env, switchFlag, handle);
    };
    return SetTouchpadBoolData(env, info, func);
}

napi_value JsPointerContext::GetTouchpadScrollSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, napi_value handle) -> napi_value {
        return jsPointerMgr->GetTouchpadScrollSwitch(env, handle);
    };
    return GetTouchpadData(env, info, func);
}

napi_value JsPointerContext::SetTouchpadScrollDirection(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, bool state, napi_value handle) -> napi_value {
        return jsPointerMgr->SetTouchpadScrollDirection(env, state, handle);
    };
    return SetTouchpadBoolData(env, info, func);
}

napi_value JsPointerContext::GetTouchpadScrollDirection(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, napi_value handle) -> napi_value {
        return jsPointerMgr->GetTouchpadScrollDirection(env, handle);
    };
    return GetTouchpadData(env, info, func);
}

napi_value JsPointerContext::SetTouchpadTapSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, bool switchFlag, napi_value handle) -> napi_value {
        return jsPointerMgr->SetTouchpadTapSwitch(env, switchFlag, handle);
    };
    return SetTouchpadBoolData(env, info, func);
}

napi_value JsPointerContext::GetTouchpadTapSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, napi_value handle) -> napi_value {
        return jsPointerMgr->GetTouchpadTapSwitch(env, handle);
    };
    return GetTouchpadData(env, info, func);
}

napi_value JsPointerContext::SetTouchpadPointerSpeed(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, int32_t data, napi_value handle) -> napi_value {
        return jsPointerMgr->SetTouchpadPointerSpeed(env, data, handle);
    };
    return SetTouchpadInt32Data(env, info, func, MAX_SPEED, MIN_SPEED);
}

napi_value JsPointerContext::GetTouchpadPointerSpeed(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, napi_value handle) -> napi_value {
        return jsPointerMgr->GetTouchpadPointerSpeed(env, handle);
    };
    return GetTouchpadData(env, info, func);
}

napi_value JsPointerContext::SetTouchpadPinchSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, bool switchFlag, napi_value handle) -> napi_value {
        return jsPointerMgr->SetTouchpadPinchSwitch(env, switchFlag, handle);
    };
    return SetTouchpadBoolData(env, info, func);
}

napi_value JsPointerContext::GetTouchpadPinchSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, napi_value handle) -> napi_value {
        return jsPointerMgr->GetTouchpadPinchSwitch(env, handle);
    };
    return GetTouchpadData(env, info, func);
}

napi_value JsPointerContext::SetTouchpadSwipeSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, bool switchFlag, napi_value handle) -> napi_value {
        return jsPointerMgr->SetTouchpadSwipeSwitch(env, switchFlag, handle);
    };
    return SetTouchpadBoolData(env, info, func);
}

napi_value JsPointerContext::GetTouchpadSwipeSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, napi_value handle) -> napi_value {
        return jsPointerMgr->GetTouchpadSwipeSwitch(env, handle);
    };
    return GetTouchpadData(env, info, func);
}

napi_value JsPointerContext::SetTouchpadRightClickType(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, int32_t data, napi_value handle) -> napi_value {
        return jsPointerMgr->SetTouchpadRightClickType(env, data, handle);
    };
    return SetTouchpadInt32Data(env, info, func, MAX_SPEED, MIN_SPEED);
}

napi_value JsPointerContext::GetTouchpadRightClickType(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, napi_value handle) -> napi_value {
        return jsPointerMgr->GetTouchpadRightClickType(env, handle);
    };
    return GetTouchpadData(env, info, func);
}

napi_value JsPointerContext::SetTouchpadRotateSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, bool rotateSwitch, napi_value handle) -> napi_value {
        return jsPointerMgr->SetTouchpadRotateSwitch(env, rotateSwitch, handle);
    };
    return SetTouchpadBoolData(env, info, func);
}

napi_value JsPointerContext::GetTouchpadRotateSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, napi_value handle) -> napi_value {
        return jsPointerMgr->GetTouchpadRotateSwitch(env, handle);
    };
    return GetTouchpadData(env, info, func);
}

napi_value JsPointerContext::SetTouchpadThreeFingersTapSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, bool switchFlag, napi_value handle) -> napi_value {
        return jsPointerMgr->SetTouchpadThreeFingersTapSwitch(env, switchFlag, handle);
    };
    return SetTouchpadBoolData(env, info, func);
}

napi_value JsPointerContext::GetTouchpadThreeFingersTapSwitch(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    CHKPP(jsPointerMgr);
    auto func = [jsPointerMgr] (napi_env env, napi_value handle) -> napi_value {
        return jsPointerMgr->GetTouchpadThreeFingersTapSwitch(env, handle);
    };
    return GetTouchpadData(env, info, func);
}

napi_value JsPointerContext::EnableHardwareCursorStats(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        MMI_HILOGE("At least one parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "enable", "boolean");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_boolean)) {
        MMI_HILOGE("Enable parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "enable", "boolean");
        return nullptr;
    }
    bool enable = true;
    CHKRP(napi_get_value_bool(env, argv[0], &enable), GET_VALUE_BOOL);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    return jsPointerMgr->EnableHardwareCursorStats(env, enable);
}

napi_value JsPointerContext::GetHardwareCursorStats(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 0) {
        return jsPointerMgr->GetHardwareCursorStats(env);
    }
    return nullptr;
}

napi_value JsPointerContext::SetTouchpadScrollRows(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "touchpadScrollRows", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("rows parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "touchpadScrollRows", "number");
        return nullptr;
    }
    int32_t rows = DEFAULT_ROWS;
    CHKRP(napi_get_value_int32(env, argv[0], &rows), GET_VALUE_INT32);
    int32_t newRows = std::clamp(rows, MIN_ROWS, MAX_ROWS);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetTouchpadScrollRows(env, newRows);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetTouchpadScrollRows(env, newRows, argv[1]);
}

napi_value JsPointerContext::GetTouchpadScrollRows(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 0) {
        return jsPointerMgr->GetTouchpadScrollRows(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->GetTouchpadScrollRows(env, argv[0]);
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
        DECLARE_NAPI_STATIC_FUNCTION("setPointerVisibleSync", SetPointerVisibleSync),
        DECLARE_NAPI_STATIC_FUNCTION("isPointerVisible", IsPointerVisible),
        DECLARE_NAPI_STATIC_FUNCTION("isPointerVisibleSync", IsPointerVisibleSync),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerColor", SetPointerColor),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerColor", GetPointerColor),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerColorSync", SetPointerColorSync),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerColorSync", GetPointerColorSync),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerSpeed", SetPointerSpeed),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerSpeedSync", SetPointerSpeedSync),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerSpeed", GetPointerSpeed),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerSpeedSync", GetPointerSpeedSync),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerStyle", SetPointerStyle),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerStyleSync", SetPointerStyleSync),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerStyle", GetPointerStyle),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerStyleSync", GetPointerStyleSync),
        DECLARE_NAPI_STATIC_FUNCTION("enterCaptureMode", EnterCaptureMode),
        DECLARE_NAPI_STATIC_FUNCTION("leaveCaptureMode", LeaveCaptureMode),
        DECLARE_NAPI_STATIC_FUNCTION("setMouseScrollRows", SetMouseScrollRows),
        DECLARE_NAPI_STATIC_FUNCTION("getMouseScrollRows", GetMouseScrollRows),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerSize", SetPointerSize),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerSize", GetPointerSize),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerSizeSync", SetPointerSizeSync),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerSizeSync", GetPointerSizeSync),
        DECLARE_NAPI_STATIC_FUNCTION("setMousePrimaryButton", SetMousePrimaryButton),
        DECLARE_NAPI_STATIC_FUNCTION("getMousePrimaryButton", GetMousePrimaryButton),
        DECLARE_NAPI_STATIC_FUNCTION("setHoverScrollState", SetHoverScrollState),
        DECLARE_NAPI_STATIC_FUNCTION("getHoverScrollState", GetHoverScrollState),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadScrollSwitch", SetTouchpadScrollSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadScrollSwitch", GetTouchpadScrollSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadScrollDirection", SetTouchpadScrollDirection),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadScrollDirection", GetTouchpadScrollDirection),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadTapSwitch", SetTouchpadTapSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadTapSwitch", GetTouchpadTapSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadPointerSpeed", SetTouchpadPointerSpeed),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadPointerSpeed", GetTouchpadPointerSpeed),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadPinchSwitch", SetTouchpadPinchSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadPinchSwitch", GetTouchpadPinchSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadSwipeSwitch", SetTouchpadSwipeSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadSwipeSwitch", GetTouchpadSwipeSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadRightClickType", SetTouchpadRightClickType),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadRightClickType", GetTouchpadRightClickType),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadRotateSwitch", SetTouchpadRotateSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadRotateSwitch", GetTouchpadRotateSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("setPointerLocation", SetPointerLocation),
        DECLARE_NAPI_STATIC_FUNCTION("setCustomCursor", SetCustomCursor),
        DECLARE_NAPI_STATIC_FUNCTION("setCustomCursorSync", SetCustomCursorSync),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadThreeFingersTapSwitch", SetTouchpadThreeFingersTapSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadThreeFingersTapSwitch", GetTouchpadThreeFingersTapSwitch),
        DECLARE_NAPI_STATIC_FUNCTION("enableHardwareCursorStats", EnableHardwareCursorStats),
        DECLARE_NAPI_STATIC_FUNCTION("getHardwareCursorStats", GetHardwareCursorStats),
        DECLARE_NAPI_STATIC_FUNCTION("setTouchpadScrollRows", SetTouchpadScrollRows),
        DECLARE_NAPI_STATIC_FUNCTION("getTouchpadScrollRows", GetTouchpadScrollRows),
    };
    CHKRP(napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc), DEFINE_PROPERTIES);
    if (CreatePointerStyle(env, exports) == nullptr) {
        THROWERR(env, "Failed to create pointer style");
        return nullptr;
    }
    if (CreateMousePrimaryButton(env, exports) == nullptr) {
        THROWERR(env, "Failed to create mouse primary button");
        return nullptr;
    }
    if (CreateTouchpadRightClickType(env, exports) == nullptr) {
        THROWERR(env, "Failed to create touchpad right click type");
        return nullptr;
    }
    return exports;
}
} // namespace MMI
} // namespace OHOS
