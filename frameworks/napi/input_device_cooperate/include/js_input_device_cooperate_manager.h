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

#ifndef JS_INPUT_DEVICE_COOPERATE_MANAGER_H
#define JS_INPUT_DEVICE_COOPERATE_MANAGER_H

#include <cstdint>
#include <mutex>
#include <string>

#include <napi/native_api.h>
#include <nocopyable.h>

#include "js_event_target.h"

namespace OHOS {
namespace MMI {
class JsInputDeviceCooperateManager : public JsEventTarget {
public:
    JsInputDeviceCooperateManager() = default;
    ~JsInputDeviceCooperateManager() = default;
    DISALLOW_COPY_AND_MOVE(JsInputDeviceCooperateManager);

    napi_value Enable(napi_env env, bool enable, napi_value handle = nullptr);
    napi_value Start(napi_env env, const std::string &sinkDeviceDescriptor, int32_t srcInputDeviceId,
        napi_value handle = nullptr);
    napi_value Stop(napi_env env, napi_value handle = nullptr);
    napi_value GetState(napi_env env, const std::string &deviceDescriptor, napi_value handle = nullptr);
    void RegisterListener(napi_env env, const std::string &type, napi_value handle);
    void UnregisterListener(napi_env env, const std::string &type, napi_value handle = nullptr);
    void ResetEnv();

private:
    std::mutex mutex_;
};
} // namespace MMI
} // namespace OHOS
#endif // JS_INPUT_DEVICE_COOPERATE_MANAGER_H
