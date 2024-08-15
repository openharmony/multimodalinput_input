/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
    virtual ~JsEventTarget() = default;
    DISALLOW_COPY_AND_MOVE(JsEventTarget);
    static void EmitJsIds(sptr<JsUtil::CallbackInfo> cb, std::vector<int32_t> &ids);
    static void EmitJsDev(sptr<JsUtil::CallbackInfo> cb, std::shared_ptr<InputDevice> device);
    static void EmitSupportKeys(sptr<JsUtil::CallbackInfo> cb, std::vector<bool> &keystrokeAbility);
    static void EmitJsKeyboardType(sptr<JsUtil::CallbackInfo> cb, int32_t keyboardType);
    static void EmitJsKeyboardRepeatDelay(sptr<JsUtil::CallbackInfo> cb, int32_t delay);
    static void EmitJsKeyboardRepeatRate(sptr<JsUtil::CallbackInfo> cb, int32_t rate);
    static void EmitJsSetKeyboardRepeatDelay(sptr<JsUtil::CallbackInfo> cb, int32_t errCode);
    static void EmitJsSetKeyboardRepeatRate(sptr<JsUtil::CallbackInfo> cb, int32_t errCode);
    static void EmitJsGetIntervalSinceLastInput(sptr<JsUtil::CallbackInfo> cb, int64_t timeInterval);
    void AddListener(napi_env env, const std::string &type, napi_value handle);
    void RemoveListener(napi_env env, const std::string &type, napi_value handle);
    napi_value CreateCallbackInfo(napi_env, napi_value handle, sptr<JsUtil::CallbackInfo> cb);
    void ResetEnv();
    void OnDeviceAdded(int32_t deviceId, const std::string &type) override;
    void OnDeviceRemoved(int32_t deviceId, const std::string &type) override;

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
    static void CallKeyboardRepeatDelayAsync(uv_work_t *work, int32_t status);
    static void CallKeyboardRepeatDelayPromise(uv_work_t *work, int32_t status);
    static void CallKeyboardRepeatRateAsync(uv_work_t *work, int32_t status);
    static void CallKeyboardRepeatRatePromise(uv_work_t *work, int32_t status);
    static void CallIntervalSinceLastInputAsync(uv_work_t *work, int32_t status);
    static void CallIntervalSinceLastInputPromise(uv_work_t *work, int32_t status);
    static void EmitAddedDeviceEvent(uv_work_t *work, int32_t status);
    static void EmitRemoveDeviceEvent(uv_work_t *work, int32_t status);
    static napi_value GreateBusinessError(napi_env env, int32_t errCode, std::string errMessage);
private:
    inline static std::map<std::string, std::vector<std::unique_ptr<JsUtil::CallbackInfo>>> devListener_ {};
    bool isListeningProcess_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // JS_EVENT_TARGET_H