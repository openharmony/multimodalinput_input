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

#ifndef JS_MOUSE_CONTROLLER_NAPI_H
#define JS_MOUSE_CONTROLLER_NAPI_H

#include "napi/native_api.h"

namespace OHOS {
namespace MMI {

/**
 * @brief Create MouseController instance
 * @param env NAPI environment
 * @param info Callback info
 * @return Promise<MouseController>
 */
napi_value CreateMouseController(napi_env env, napi_callback_info info);

/**
 * @brief MouseController.moveTo() NAPI wrapper
 */
napi_value MouseControllerMoveTo(napi_env env, napi_callback_info info);

/**
 * @brief MouseController.pressButton() NAPI wrapper
 */
napi_value MouseControllerPressButton(napi_env env, napi_callback_info info);

/**
 * @brief MouseController.releaseButton() NAPI wrapper
 */
napi_value MouseControllerReleaseButton(napi_env env, napi_callback_info info);

/**
 * @brief MouseController.beginAxis() NAPI wrapper
 */
napi_value MouseControllerBeginAxis(napi_env env, napi_callback_info info);

/**
 * @brief MouseController.updateAxis() NAPI wrapper
 */
napi_value MouseControllerUpdateAxis(napi_env env, napi_callback_info info);

/**
 * @brief MouseController.endAxis() NAPI wrapper
 */
napi_value MouseControllerEndAxis(napi_env env, napi_callback_info info);

} // namespace MMI
} // namespace OHOS

#endif // JS_MOUSE_CONTROLLER_NAPI_H
