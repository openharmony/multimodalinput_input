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

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsPointerContext" };
constexpr int32_t STANDARD_SPEED = 5;
constexpr int32_t MAX_SPEED = 11;
constexpr int32_t MIN_SPEED = 1;
constexpr int32_t DEFAULT_ROWS = 3;
constexpr int32_t MIN_ROWS = 1;
constexpr int32_t MAX_ROWS = 100;
constexpr size_t INPUT_PARAMETER = 2;
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
    napi_value argv[2];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
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
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetPointerVisible(env, visible);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid ");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetPointerVisible(env, visible, argv[1]);
}

napi_value JsPointerContext::IsPointerVisible(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 0) {
        return jsPointerMgr->IsPointerVisible(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return jsPointerMgr->IsPointerVisible(env, argv[0]);
}

napi_value JsPointerContext::SetPointerSpeed(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "speed", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("speed parameter type is invalid");
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
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->SetPointerSpeed(env, pointerSpeed);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetPointerSpeed(env, pointerSpeed, argv[1]);
}

napi_value JsPointerContext::GetPointerSpeed(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 0) {
        return jsPointerMgr->GetPointerSpeed(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return jsPointerMgr->GetPointerSpeed(env, argv[0]);
}

napi_value JsPointerContext::SetMouseScrollRows(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "rows", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("rows parameter type is invalid");
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
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetMouseScrollRows(env, rows, argv[1]);
}

napi_value JsPointerContext::GetMouseScrollRows(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 0) {
        return jsPointerMgr->GetMouseScrollRows(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }

    return jsPointerMgr->GetMouseScrollRows(env, argv[0]);
}

napi_value JsPointerContext::SetPointerStyle(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3];
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
    if (windowid < 0) {
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
    if (pointerStyle < DEFAULT || pointerStyle > MIDDLE_BTN_NORTH_SOUTH_WEST_EAST) {
        MMI_HILOGE("Undefined pointer style");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Pointer style does not exist");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == INPUT_PARAMETER) {
        return jsPointerMgr->SetPointerStyle(env, windowid, pointerStyle);
    }
    if (!JsCommon::TypeOf(env, argv[INPUT_PARAMETER], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetPointerStyle(env, windowid, pointerStyle, argv[INPUT_PARAMETER]);
}

napi_value JsPointerContext::GetPointerStyle(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
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
    if (windowid < 0) {
        MMI_HILOGE("Invalid windowid");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Windowid is invalid");
        return nullptr;
    }
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 1) {
        return jsPointerMgr->GetPointerStyle(env, windowid);
    }
    if (!JsCommon::TypeOf(env, argv[1], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->GetPointerStyle(env, windowid, argv[1]);
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
    };
    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "PointerStyle", NAPI_AUTO_LENGTH, EnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "PointerStyle", result), SET_NAMED_PROPERTY);
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
    napi_value argv[2];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > INPUT_PARAMETER) {
        THROWERR(env, "The number of parameters is not as expected");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "The first parameter type is invalid");
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
        THROWERR(env, "The second parameter type is invalid");
        return nullptr;
    }
    return jsPointerMgr->EnterCaptureMode(env, windowId, argv[1]);
}

napi_value JsPointerContext::LeaveCaptureMode(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1 || argc > INPUT_PARAMETER) {
        THROWERR(env, "The number of parameters is not as expected");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        THROWERR(env, "The first parameter type is invalid");
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
        THROWERR(env, "The second parameter type is invalid");
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
    napi_value argv[2];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
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
        MMI_HILOGE("callback parameter type is invalid ");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetMousePrimaryButton(env, primaryButton, argv[1]);
}

napi_value JsPointerContext::GetMousePrimaryButton(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 0) {
        return jsPointerMgr->GetMousePrimaryButton(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->GetMousePrimaryButton(env, argv[0]);
}

napi_value JsPointerContext::SetHoverScrollState(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc == 0) {
        MMI_HILOGE("At least one parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "state", "boolean");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_boolean)) {
        MMI_HILOGE("state parameter type is invalid");
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
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->SetHoverScrollState(env, state, argv[1]);
}

napi_value JsPointerContext::GetHoverScrollState(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1];
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);

    JsPointerContext *jsPointer = JsPointerContext::GetInstance(env);
    CHKPP(jsPointer);
    auto jsPointerMgr = jsPointer->GetJsPointerMgr();
    if (argc == 0) {
        return jsPointerMgr->GetHoverScrollState(env);
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_function)) {
        MMI_HILOGE("callback parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
        return nullptr;
    }
    return jsPointerMgr->GetHoverScrollState(env, argv[0]);
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
        DECLARE_NAPI_STATIC_FUNCTION("setPointerStyle", SetPointerStyle),
        DECLARE_NAPI_STATIC_FUNCTION("getPointerStyle", GetPointerStyle),
        DECLARE_NAPI_STATIC_FUNCTION("enterCaptureMode", EnterCaptureMode),
        DECLARE_NAPI_STATIC_FUNCTION("leaveCaptureMode", LeaveCaptureMode),
        DECLARE_NAPI_STATIC_FUNCTION("setMouseScrollRows", SetMouseScrollRows),
        DECLARE_NAPI_STATIC_FUNCTION("getMouseScrollRows", GetMouseScrollRows),
        DECLARE_NAPI_STATIC_FUNCTION("setMousePrimaryButton", SetMousePrimaryButton),
        DECLARE_NAPI_STATIC_FUNCTION("getMousePrimaryButton", GetMousePrimaryButton),
        DECLARE_NAPI_STATIC_FUNCTION("setHoverScrollState", SetHoverScrollState),
        DECLARE_NAPI_STATIC_FUNCTION("getHoverScrollState", GetHoverScrollState),
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
    return exports;
}
} // namespace MMI
} // namespace OHOS
