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

#ifndef JS_POINTER_CONTEXT_H
#define JS_POINTER_CONTEXT_H
#include "js_pointer_manager.h"

namespace OHOS {
namespace MMI {
class JsPointerContext {
using SetTouchpadBoolDataFunc = std::function<napi_value (napi_env env, bool data, napi_value handle)>;
using SetTouchpadInt32DataFunc = std::function<napi_value (napi_env env, int32_t data, napi_value handle)>;
using GetTouchpadFunc = std::function<napi_value (napi_env env, napi_value handle)>;

public:
    JsPointerContext();
    DISALLOW_COPY_AND_MOVE(JsPointerContext);
    ~JsPointerContext() = default;
    static napi_value Export(napi_env env, napi_value exports);
    static napi_value SetPointerVisible(napi_env env, napi_callback_info info);
    static napi_value SetPointerVisibleSync(napi_env env, napi_callback_info info);
    static napi_value IsPointerVisible(napi_env env, napi_callback_info info);
    static napi_value IsPointerVisibleSync(napi_env env, napi_callback_info info);
    static napi_value SetPointerStyle(napi_env env, napi_callback_info info);
    static napi_value SetPointerStyleSync(napi_env env, napi_callback_info info);
    static napi_value GetPointerStyle(napi_env env, napi_callback_info info);
    static napi_value GetPointerStyleSync(napi_env env, napi_callback_info info);
    std::shared_ptr<JsPointerManager> GetJsPointerMgr() const;
    static napi_value SetPointerColor(napi_env env, napi_callback_info info);
    static napi_value GetPointerColor(napi_env env, napi_callback_info info);
    static napi_value SetPointerColorSync(napi_env env, napi_callback_info info);
    static napi_value GetPointerColorSync(napi_env env, napi_callback_info info);
    static napi_value SetPointerSpeed(napi_env env, napi_callback_info info);
    static napi_value SetPointerSpeedSync(napi_env env, napi_callback_info info);
    static napi_value GetPointerSpeed(napi_env env, napi_callback_info info);
    static napi_value GetPointerSpeedSync(napi_env env, napi_callback_info info);
    static napi_value SetPointerLocation(napi_env env, napi_callback_info info);
    static napi_value EnterCaptureMode(napi_env env, napi_callback_info info);
    static napi_value LeaveCaptureMode(napi_env env, napi_callback_info info);
    static napi_value SetMouseScrollRows(napi_env env, napi_callback_info info);
    static napi_value GetMouseScrollRows(napi_env env, napi_callback_info info);
    static napi_value SetPointerSize(napi_env env, napi_callback_info info);
    static napi_value GetPointerSize(napi_env env, napi_callback_info info);
    static napi_value SetPointerSizeSync(napi_env env, napi_callback_info info);
    static napi_value GetPointerSizeSync(napi_env env, napi_callback_info info);
    static napi_value SetMousePrimaryButton(napi_env env, napi_callback_info info);
    static napi_value GetMousePrimaryButton(napi_env env, napi_callback_info info);
    static napi_value SetHoverScrollState(napi_env env, napi_callback_info info);
    static napi_value GetHoverScrollState(napi_env env, napi_callback_info info);
    static napi_value SetTouchpadScrollSwitch(napi_env env, napi_callback_info info);
    static napi_value GetTouchpadScrollSwitch(napi_env env, napi_callback_info info);
    static napi_value SetTouchpadScrollDirection(napi_env env, napi_callback_info info);
    static napi_value GetTouchpadScrollDirection(napi_env env, napi_callback_info info);
    static napi_value SetTouchpadTapSwitch(napi_env env, napi_callback_info info);
    static napi_value GetTouchpadTapSwitch(napi_env env, napi_callback_info info);
    static napi_value SetTouchpadPointerSpeed(napi_env env, napi_callback_info info);
    static napi_value GetTouchpadPointerSpeed(napi_env env, napi_callback_info info);
    static napi_value SetTouchpadPinchSwitch(napi_env env, napi_callback_info info);
    static napi_value GetTouchpadPinchSwitch(napi_env env, napi_callback_info info);
    static napi_value SetTouchpadSwipeSwitch(napi_env env, napi_callback_info info);
    static napi_value GetTouchpadSwipeSwitch(napi_env env, napi_callback_info info);
    static napi_value SetTouchpadRightClickType(napi_env env, napi_callback_info info);
    static napi_value GetTouchpadRightClickType(napi_env env, napi_callback_info info);
    static napi_value SetTouchpadRotateSwitch(napi_env env, napi_callback_info info);
    static napi_value GetTouchpadRotateSwitch(napi_env env, napi_callback_info info);
    static napi_value SetCustomCursor(napi_env env, napi_callback_info info);
    static napi_value SetCustomCursorSync(napi_env env, napi_callback_info info);
    static napi_value SetTouchpadThreeFingersTapSwitch(napi_env env, napi_callback_info info);
    static napi_value GetTouchpadThreeFingersTapSwitch(napi_env env, napi_callback_info info);
    static napi_value EnableHardwareCursorStats(napi_env env, napi_callback_info info);
    static napi_value GetHardwareCursorStats(napi_env env, napi_callback_info info);

private:
    static napi_value SetTouchpadBoolData(napi_env env, napi_callback_info info, SetTouchpadBoolDataFunc func);
    static napi_value SetTouchpadInt32Data(napi_env env, napi_callback_info info, SetTouchpadInt32DataFunc func,
        int32_t dataMax, int32_t dataMin);
    static napi_value GetTouchpadData(napi_env env, napi_callback_info info, GetTouchpadFunc func);
    static napi_value CreateInstance(napi_env env);
    static JsPointerContext* GetInstance(napi_env env);
    static napi_value CreateJsObject(napi_env env, napi_callback_info info);
    static napi_value EnumConstructor(napi_env env, napi_callback_info info);
    static napi_value CreatePointerStyle(napi_env env, napi_value exports);
    static napi_value CreateMousePrimaryButton(napi_env env, napi_value exports);
    static napi_value CreateTouchpadRightClickType(napi_env env, napi_value exports);
    static int32_t GetWindowId(napi_env env, napi_value value);
    static int32_t GetCursorFocusX(napi_env env, napi_value value);
    static int32_t GetCursorFocusY(napi_env env, napi_value value);
    std::shared_ptr<JsPointerManager> mgr_ { nullptr };
    napi_ref contextRef_ { nullptr };
};
} // namespace MMI
} // namespace OHOS
#endif // JS_POINTER_CONTEXT_H