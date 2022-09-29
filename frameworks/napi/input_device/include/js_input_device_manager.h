/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef JS_INPUT_DEVICE_MANAGER_H
#define JS_INPUT_DEVICE_MANAGER_H

#include <memory>
#include "js_event_target.h"

namespace OHOS {
namespace MMI {
class JsInputDeviceManager : public JsEventTarget {
public:
    JsInputDeviceManager() = default;
    DISALLOW_COPY_AND_MOVE(JsInputDeviceManager);
    ~JsInputDeviceManager() = default;

    void ResetEnv();
    napi_value GetDeviceIds(napi_env env, napi_value handle = nullptr);
    napi_value GetDevice(napi_env env, int32_t id, napi_value handle = nullptr);
    napi_value SupportKeys(napi_env env, int32_t id, std::vector<int32_t> &keyCodes,
                                   napi_value handle = nullptr);
    napi_value GetKeyboardType(napi_env env, int32_t id, napi_value handle = nullptr);
    void RegisterDevListener(napi_env env, const std::string &type, napi_value handle);
    void UnregisterDevListener(napi_env env, const std::string &type, napi_value handle = nullptr);
    napi_value GetDeviceList(napi_env env, napi_value handle = nullptr);
    napi_value GetDeviceInfo(napi_env env, int32_t id, napi_value handle = nullptr);
};
} // namespace MMI
} // namespace OHOS

#endif // JS_INPUT_DEVICE_MANAGER_H