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

#include "js_gesture_event.h"

#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsGestureEvent"
namespace OHOS {
namespace MMI {

enum class ActionType : int32_t {
    CANCEL = 0,
    BEGIN = 1,
    UPDATE = 2,
    END = 3,
};

napi_value JsGestureEvent::GetNapiInt32(napi_env env, int32_t code)
{
    CALL_DEBUG_ENTER;
    napi_value ret = nullptr;
    CHKRP(napi_create_int32(env, code, &ret), CREATE_INT32);
    return ret;
}

napi_value JsGestureEvent::GetNapiString(napi_env env, std::string str)
{
    CALL_DEBUG_ENTER;
    napi_value ret = nullptr;
    CHKRP(napi_create_string_utf8(env, str.c_str(), NAPI_AUTO_LENGTH, &ret), CREATE_STRING_UTF8);
    return ret;
}

napi_value JsGestureEvent::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsGestureEvent::Export(napi_env env, napi_value exports)
{
    CALL_INFO_TRACE;
    napi_property_descriptor actionArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL", GetNapiInt32(env, static_cast<int32_t>(ActionType::CANCEL))),
        DECLARE_NAPI_STATIC_PROPERTY("BEGIN", GetNapiInt32(env, static_cast<int32_t>(ActionType::BEGIN))),
        DECLARE_NAPI_STATIC_PROPERTY("UPDATE", GetNapiInt32(env, static_cast<int32_t>(ActionType::UPDATE))),
        DECLARE_NAPI_STATIC_PROPERTY("END", GetNapiInt32(env, static_cast<int32_t>(ActionType::END))),
    };
    napi_value actionType = nullptr;
    CHKRP(napi_define_class(env, "ActionType", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(actionArr) / sizeof(*actionArr), actionArr, &actionType), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "ActionType", actionType), SET_NAMED_PROPERTY);

    napi_property_descriptor gestureActionArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("SWIPE_DOWN",
            GetNapiInt32(env, static_cast<int32_t>(TouchGesturAction::SWIPE_DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("SWIPE_UP",
            GetNapiInt32(env, static_cast<int32_t>(TouchGesturAction::SWIPE_UP))),
        DECLARE_NAPI_STATIC_PROPERTY("SWIPE_LEFT",
            GetNapiInt32(env, static_cast<int32_t>(TouchGesturAction::SWIPE_LEFT))),
        DECLARE_NAPI_STATIC_PROPERTY("SWIPE_RIGHT",
            GetNapiInt32(env, static_cast<int32_t>(TouchGesturAction::SWIPE_RIGHT))),
        DECLARE_NAPI_STATIC_PROPERTY("PINCH_CLOSED",
            GetNapiInt32(env, static_cast<int32_t>(TouchGesturAction::PINCH_CLOSED))),
        DECLARE_NAPI_STATIC_PROPERTY("PINCH_OPENED",
            GetNapiInt32(env, static_cast<int32_t>(TouchGesturAction::PINCH_OPENED))),
        DECLARE_NAPI_STATIC_PROPERTY("GESTURE_END",
            GetNapiInt32(env, static_cast<int32_t>(TouchGesturAction::GESTURE_END))),
    };
    napi_value gestureActionType = nullptr;
    CHKRP(napi_define_class(env, "TouchGestureAction", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(gestureActionArr) / sizeof(*gestureActionArr), gestureActionArr, &gestureActionType), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "TouchGestureAction", gestureActionType), SET_NAMED_PROPERTY);
    return exports;
}
} // namespace MMI
} // namespace OHOS