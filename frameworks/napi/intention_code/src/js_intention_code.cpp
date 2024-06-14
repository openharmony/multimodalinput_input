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

#include "js_intention_code.h"

#include "key_event.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsIntentionCode"

namespace OHOS {
namespace MMI {

napi_value JsIntentionCode::GetNapiInt32(napi_env env, int32_t code)
{
    CALL_DEBUG_ENTER;
    napi_value intentionCode = nullptr;
    CHKRP(napi_create_int32(env, code, &intentionCode), CREATE_INT32);
    return intentionCode;
}

napi_value JsIntentionCode::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsIntentionCode::Export(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_UNKNOWN", GetNapiInt32(env, KeyEvent::INTENTION_UNKNOWN)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_UP", GetNapiInt32(env, KeyEvent::INTENTION_UP)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_DOWN", GetNapiInt32(env, KeyEvent::INTENTION_DOWN)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_LEFT", GetNapiInt32(env, KeyEvent::INTENTION_LEFT)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_RIGHT", GetNapiInt32(env, KeyEvent::INTENTION_RIGHT)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_SELECT", GetNapiInt32(env, KeyEvent::INTENTION_SELECT)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_ESCAPE", GetNapiInt32(env, KeyEvent::INTENTION_ESCAPE)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_BACK", GetNapiInt32(env, KeyEvent::INTENTION_BACK)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_FORWARD", GetNapiInt32(env, KeyEvent::INTENTION_FORWARD)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_MENU", GetNapiInt32(env, KeyEvent::INTENTION_MENU)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_PAGE_UP", GetNapiInt32(env, KeyEvent::INTENTION_PAGE_UP)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_PAGE_DOWN", GetNapiInt32(env, KeyEvent::INTENTION_PAGE_DOWN)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_ZOOM_OUT", GetNapiInt32(env, KeyEvent::INTENTION_ZOOM_OUT)),
        DECLARE_NAPI_STATIC_PROPERTY("INTENTION_ZOOM_IN", GetNapiInt32(env, KeyEvent::INTENTION_ZOOM_IN)),
    };

    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "IntentionCode", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "IntentionCode", result), SET_NAMED_PROPERTY);
    return exports;
}
} // namespace MMI
} // namespace OHOS