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

#include "js_key_event.h"

#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsKeyEvent"

namespace OHOS {
namespace MMI {
namespace {
enum class Action : int32_t {
    CANCEL = 0,
    DOWN = 1,
    UP = 2,
};
} // namespace

napi_value JsKeyEvent::GetNapiInt32(napi_env env, int32_t code)
{
    CALL_DEBUG_ENTER;
    napi_value ret = nullptr;
    CHKRP(napi_create_int32(env, code, &ret), CREATE_INT32);
    return ret;
}

napi_value JsKeyEvent::EnumClassConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

napi_value JsKeyEvent::Export(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("CANCEL", GetNapiInt32(env, static_cast<int32_t>(Action::CANCEL))),
        DECLARE_NAPI_STATIC_PROPERTY("DOWN", GetNapiInt32(env, static_cast<int32_t>(Action::DOWN))),
        DECLARE_NAPI_STATIC_PROPERTY("UP", GetNapiInt32(env, static_cast<int32_t>(Action::UP))),
    };

    napi_value action = nullptr;
    CHKRP(napi_define_class(env, "Action", NAPI_AUTO_LENGTH, EnumClassConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &action), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "Action", action), SET_NAMED_PROPERTY);
    return exports;
}
} // namespace MMI
} // namespace OHOS