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

#include "input_manager.h"
#include "js_util.h"

namespace OHOS {
namespace MMI {
class JsEventTarget : public IInputDeviceListener, public std::enable_shared_from_this<JsEventTarget> {
public:
    JsEventTarget();
    ~JsEventTarget();
    DISALLOW_COPY_AND_MOVE(JsEventTarget);
    static void EmitJsIds(int32_t userData, std::vector<int32_t> &ids);
    static void EmitJsDev(int32_t userData, std::shared_ptr<InputDevice> device);
    static void EmitSupportKeys(int32_t userData, std::vector<bool> &keystrokeAbility);
    static void EmitJsKeyboardType(int32_t userData, int32_t keyboardType);
    void AddListener(napi_env env, const std::string &type, napi_value handle);
    void RemoveListener(napi_env env, const std::string &type, napi_value handle);
    void RemoveCallbackInfo(napi_env env, napi_value handle, int32_t userData);
    napi_value CreateCallbackInfo(napi_env env, napi_value handle, const int32_t userData, bool isApi9 = false);
    void ResetEnv();
    virtual void OnDeviceAdded(int32_t deviceId, const std::string &type) override;
    virtual void OnDeviceRemoved(int32_t deviceId, const std::string &type) override;

private:
    static void CallIdsPromiseWork(uv_work_t *work, int32_t status);
    static void CallIdsAsyncWork(uv_work_t *work, int32_t status);
    static void CallDevAsyncWork(uv_work_t *work, int32_t status);
    static void CallDevPromiseWork(uv_work_t *work, int32_t status);
    static void CallKeystrokeAbilityPromise(uv_work_t *work, int32_t status);
    static void CallKeystrokeAbilityAsync(uv_work_t *work, int32_t status);
    static void CallKeyboardTypeAsync(uv_work_t *work, int32_t status);
    static void CallKeyboardTypePromise(uv_work_t *work, int32_t status);
    static void CallDevListPromiseWork(uv_work_t *work, int32_t status);
    static void CallDevListAsyncWork(uv_work_t *work, int32_t status);
    static void CallDevInfoAsyncWork(uv_work_t *work, int32_t status);
    static void CallDevInfoPromiseWork(uv_work_t *work, int32_t status);
    static void EmitAddedDeviceEvent(uv_work_t *work, int32_t status);
    static void EmitRemoveDeviceEvent(uv_work_t *work, int32_t status);
    static std::unique_ptr<JsUtil::CallbackInfo> GetCallbackInfo(uv_work_t *work);
    static napi_value GreateBusinessError(napi_env env, int32_t errCode, std::string errMessage);
private:
    inline static std::map<int32_t, std::unique_ptr<JsUtil::CallbackInfo>> callback_ {};
    inline static std::map<std::string, std::vector<std::unique_ptr<JsUtil::CallbackInfo>>> devListener_ {};
    bool isListeningProcess_ { false };
};
} // namespace MMI
} // namespace OHOS

#endif // JS_EVENT_TARGET_H