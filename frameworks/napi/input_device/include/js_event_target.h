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

#include "define_multimodal.h"
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
    static void EmitJsDev(sptr<JsUtil::CallbackInfo> cb, int32_t deviceid);
    static void EmitSupportKeys(sptr<JsUtil::CallbackInfo> cb, std::vector<int32_t> &keycode, int32_t id);
    static void EmitJsKeyboardType(sptr<JsUtil::CallbackInfo> cb, int32_t deviceid);
    static void EmitJsKeyboardRepeatDelay(sptr<JsUtil::CallbackInfo> cb, int32_t delay);
    static void EmitJsKeyboardRepeatRate(sptr<JsUtil::CallbackInfo> cb, int32_t rate);
    static void EmitJsSetKeyboardRepeatDelay(sptr<JsUtil::CallbackInfo> cb, int32_t delay);
    static void EmitJsSetKeyboardRepeatRate(sptr<JsUtil::CallbackInfo> cb, int32_t rate);
    static void EmitJsGetIntervalSinceLastInput(sptr<JsUtil::CallbackInfo> cb);
    void AddListener(napi_env env, const std::string &type, napi_value handle);
    void RemoveListener(napi_env env, const std::string &type, napi_value handle);
    napi_value CreateCallbackInfo(napi_env, napi_value handle, sptr<JsUtil::CallbackInfo> cb);
    void ResetEnv();
    void OnDeviceAdded(int32_t deviceId, const std::string &type) override;
    void OnDeviceRemoved(int32_t deviceId, const std::string &type) override;
    static void EmitJsSetInputDeviceEnabled(sptr<JsUtil::CallbackInfo> cb, int32_t errCode);
    static void EmitJsSetFunctionKeyState(sptr<JsUtil::CallbackInfo> cb, int32_t funcKey, bool state);
    static void EmitJsGetFunctionKeyState(sptr<JsUtil::CallbackInfo> cb, int32_t funcKey);
    static void CallFunctionKeyStateTask(uv_work_t *work);
    static void CallFunctionKeyState(uv_work_t *work, int32_t status);
    static bool GetFunctionKeyStateErrCode(sptr<JsUtil::CallbackInfo> cb,
        napi_handle_scope scope, napi_value &callResult);
    static void EmitJsDevInternal(sptr<JsUtil::CallbackInfo> cb);
    static void EmitJsIdsInternal(sptr<JsUtil::CallbackInfo> cb);
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
    static void CallIntervalSinceLastInputPromise(uv_work_t *work, int32_t status);
    static void EmitAddedDeviceEvent(sptr<JsUtil::ReportData> reportData);
    static void EmitRemoveDeviceEvent(sptr<JsUtil::ReportData> reportData);
    static napi_value GreateBusinessError(napi_env env, int32_t errCode, std::string errMessage);
    static void CallSetInputDeviceEnabledPromise(uv_work_t *work, int32_t status);
    static void CallKeyboardRepeatDelayTask(uv_work_t *work, const std::string& operateType);
    static void CallKeyboardRepeatRateTask(uv_work_t *work, const std::string& operateType);
    static void CallGetKeyboardTypeTask(uv_work_t *work);
    static void CallJsIdsTask(uv_work_t *work);
    static void CallJsDevTask(uv_work_t *work);
    static void CallSupportKeysTask(uv_work_t *work);
    static void CallIntervalSinceLastInputTask(uv_work_t *work);
private:
    inline static std::map<std::string, std::vector<std::unique_ptr<JsUtil::CallbackInfo>>> devListener_ {};
    bool isListeningProcess_ { false };
};
} // namespace MMI
} // namespace OHOS
#endif // JS_EVENT_TARGET_H