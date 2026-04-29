/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef JS_TOUCH_CONTROLLER_NAPI_H
#define JS_TOUCH_CONTROLLER_NAPI_H

#include "napi/native_api.h"

namespace OHOS {
namespace MMI {
struct TouchPointParams {
    int32_t id = 0;
    int32_t displayId = 0;
    int32_t displayX = 0;
    int32_t displayY = 0;
};

napi_value CreateTouchController(napi_env env, napi_callback_info info);
napi_value TouchControllerTouchDown(napi_env env, napi_callback_info info);
napi_value TouchControllerTouchMove(napi_env env, napi_callback_info info);
napi_value TouchControllerTouchUp(napi_env env, napi_callback_info info);

} // namespace MMI
} // namespace OHOS

#endif // JS_TOUCH_CONTROLLER_NAPI_H
