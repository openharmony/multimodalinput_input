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

#ifndef JS_EVENT_TARGET_H
#define JS_EVENT_TARGET_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "util_napi.h"
#include "utils/log.h"

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_device_impl.h"

#include "js_util.h"

namespace OHOS {
namespace MMI {
class JsEventTarget {
public:
    JsEventTarget();
    ~JsEventTarget();
    DISALLOW_COPY_AND_MOVE(JsEventTarget);
    static void TargetOn(std::string type, int32_t deviceId);
    static void EmitJsIds(int32_t userData, std::vector<int32_t> ids);
    static void EmitJsDev(int32_t userData, std::shared_ptr<InputDeviceImpl::InputDeviceInfo> device);
    static void EmitJsKeystrokeAbility(int32_t userData, std::vector<int32_t> keystrokeAbility);
    void AddMonitor(napi_env env, std::string type, napi_value handle);
    void RemoveMonitor(napi_env env, std::string type, napi_value handle);
    napi_value CreateCallbackInfo(napi_env env, napi_value handle);
    void ResetEnv();
    inline static int32_t userData_ {0};
    inline static std::map<int32_t, std::unique_ptr<JsUtil::CallbackInfo>> callback_ {};
    inline static std::map<std::string, std::vector<std::unique_ptr<JsUtil::CallbackInfo>>> devMonitor_ {};

    struct DeviceType {
        std::string deviceTypeName;
        uint32_t typeBit;
    };

private:
    static void CallIdsPromiseWork(uv_work_t *work, int32_t status);
    static void CallIdsAsyncWork(uv_work_t *work, int32_t status);
    static void CallDevAsyncWork(uv_work_t *work, int32_t status);
    static void CallDevPromiseWork(uv_work_t *work, int32_t status);
    static void CallKeystrokeAbilityPromise(uv_work_t *work, int32_t status);
    static void CallKeystrokeAbilityAsync(uv_work_t *work, int32_t status);
    static void EmitAddedDeviceEvent(uv_work_t *work, int32_t status);
    static void EmitRemoveDeviceEvent(uv_work_t *work, int32_t status);
};
} // namespace MMI
} // namespace OHOS

#endif // JS_EVENT_TARGET_H