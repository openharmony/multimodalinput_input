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

#include "js_touch_event.h"

#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsMouseEvent"

namespace OHOS {
namespace MMI {
napi_value JsTouchEvent::GetNapiInt32(napi_env env, int32_t code)
{
    CALL_DEBUG_ENTER;
    napi_value ret = nullptr;
    CHKRP(napi_create_int32(env, code, &ret), CREATE_INT32);
    return ret;
}

napi_value JsTouchEvent::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsTouchEvent::Export(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor actionArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL", GetNapiInt32(env, static_cast<int32_t>(Action::CANCEL))),
        DECLARE_NAPI_STATIC_PROPERTY("DOWN", GetNapiInt32(env, static_cast<int32_t>(Action::DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("MOVE", GetNapiInt32(env, static_cast<int32_t>(Action::MOVE))),
        DECLARE_NAPI_STATIC_PROPERTY("UP", GetNapiInt32(env, static_cast<int32_t>(Action::UP))),
        DECLARE_NAPI_STATIC_PROPERTY("PULL_DOWN", GetNapiInt32(env, static_cast<int32_t>(Action::PULL_DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("PULL_MOVE", GetNapiInt32(env, static_cast<int32_t>(Action::PULL_MOVE))),
        DECLARE_NAPI_STATIC_PROPERTY("PULL_UP", GetNapiInt32(env, static_cast<int32_t>(Action::PULL_UP))),
    };
    napi_value action = nullptr;
    CHKRP(napi_define_class(env, "Action", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(actionArr) / sizeof(*actionArr), actionArr, &action), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "Action", action), SET_NAMED_PROPERTY);

    napi_property_descriptor toolTypeArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("FINGER", GetNapiInt32(env, static_cast<int32_t>(ToolType::FINGER))),
        DECLARE_NAPI_STATIC_PROPERTY("PEN", GetNapiInt32(env, static_cast<int32_t>(ToolType::PEN))),
        DECLARE_NAPI_STATIC_PROPERTY("RUBBER", GetNapiInt32(env, static_cast<int32_t>(ToolType::RUBBER))),
        DECLARE_NAPI_STATIC_PROPERTY("BRUSH", GetNapiInt32(env, static_cast<int32_t>(ToolType::BRUSH))),
        DECLARE_NAPI_STATIC_PROPERTY("PENCIL", GetNapiInt32(env, static_cast<int32_t>(ToolType::PENCIL))),
        DECLARE_NAPI_STATIC_PROPERTY("AIRBRUSH", GetNapiInt32(env, static_cast<int32_t>(ToolType::AIRBRUSH))),
        DECLARE_NAPI_STATIC_PROPERTY("MOUSE", GetNapiInt32(env, static_cast<int32_t>(ToolType::MOUSE))),
        DECLARE_NAPI_STATIC_PROPERTY("LENS", GetNapiInt32(env, static_cast<int32_t>(ToolType::LENS))),
    };
    napi_value toolType = nullptr;
    CHKRP(napi_define_class(env, "ToolType", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(toolTypeArr) / sizeof(*toolTypeArr), toolTypeArr, &toolType), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "ToolType", toolType), SET_NAMED_PROPERTY);

    napi_property_descriptor sourceTypeArr[] = {
        DECLARE_NAPI_STATIC_PROPERTY("TOUCH_SCREEN", GetNapiInt32(env, static_cast<int32_t>(SourceType::TOUCH_SCREEN))),
        DECLARE_NAPI_STATIC_PROPERTY("PEN", GetNapiInt32(env, static_cast<int32_t>(SourceType::PEN))),
        DECLARE_NAPI_STATIC_PROPERTY("TOUCH_PAD", GetNapiInt32(env, static_cast<int32_t>(SourceType::TOUCH_PAD))),
    };
    napi_value sourceType = nullptr;
    CHKRP(napi_define_class(env, "SourceType", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(sourceTypeArr) / sizeof(*sourceTypeArr), sourceTypeArr, &sourceType), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "SourceType", sourceType), SET_NAMED_PROPERTY);
    return exports;
}
} // namespace MMI
} // namespace OHOS