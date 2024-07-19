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

#ifndef JS_POINTER_MANAGER_H
#define JS_POINTER_MANAGER_H

#include <memory>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "refbase.h"
#include "utils/log.h"

#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_manager.h"
#include "napi_constants.h"
#include "pointer_style.h"
#include "stream_buffer.h"
#include "util_napi.h"
#include "util_napi_error.h"

namespace OHOS {
namespace MMI {
class JsCommon {
public:
    static bool TypeOf(napi_env env, napi_value value, napi_valuetype type);
};

struct AsyncContext : RefBase {
    napi_env env { nullptr };
    napi_async_work work { nullptr };
    napi_deferred deferred { nullptr };
    napi_ref callback { nullptr };
    int32_t errorCode { -1 };
    StreamBuffer reserve;
    AsyncContext(napi_env env) : env(env) {}
    ~AsyncContext();
};

class JsPointerManager final {
public:
    JsPointerManager() = default;
    ~JsPointerManager() = default;
    DISALLOW_COPY_AND_MOVE(JsPointerManager);

    void ResetEnv();
    napi_value SetPointerVisible(napi_env env, bool visible, napi_value handle = nullptr);
    napi_value SetPointerVisibleSync(napi_env env, bool visible);
    napi_value IsPointerVisible(napi_env env, napi_value handle = nullptr);
    napi_value IsPointerVisibleSync(napi_env env);
    napi_value SetPointerColor(napi_env env, int32_t color, napi_value handle = nullptr);
    napi_value GetPointerColor(napi_env env, napi_value handle = nullptr);
    napi_value SetPointerColorSync(napi_env env, int32_t color);
    napi_value GetPointerColorSync(napi_env env);
    napi_value SetPointerSpeed(napi_env env, int32_t pointerSpeed, napi_value handle = nullptr);
    napi_value SetPointerSpeedSync(napi_env env, int32_t pointerSpeed);
    napi_value GetPointerSpeed(napi_env env, napi_value handle = nullptr);
    napi_value GetPointerSpeedSync(napi_env env);
    napi_value SetPointerStyle(napi_env env, int32_t windowid, int32_t pointerStyle, napi_value handle = nullptr);
    napi_value SetPointerStyleSync(napi_env env, int32_t windowid, int32_t pointerStyle);
    napi_value GetPointerStyle(napi_env env, int32_t windowid, napi_value handle = nullptr);
    napi_value GetPointerStyleSync(napi_env env, int32_t windowid);
    napi_value SetPointerLocation(napi_env env, int32_t x, int32_t y, napi_value handle = nullptr);
    napi_value EnterCaptureMode(napi_env env, int32_t windowId, napi_value handle = nullptr);
    napi_value LeaveCaptureMode(napi_env env, int32_t windowId, napi_value handle = nullptr);
    napi_value SetMouseScrollRows(napi_env env, int32_t rows, napi_value handle = nullptr);
    napi_value GetMouseScrollRows(napi_env env, napi_value handle = nullptr);
    napi_value SetCustomCursor(napi_env env, int32_t windowId, void* pixelMap, CursorFocus focus);
    napi_value SetCustomCursorSync(napi_env env, int32_t windowId, void* pixelMap, CursorFocus focus);
    napi_value SetPointerSize(napi_env env, int32_t size, napi_value handle = nullptr);
    napi_value GetPointerSize(napi_env env, napi_value handle = nullptr);
    napi_value SetPointerSizeSync(napi_env env, int32_t size);
    napi_value GetPointerSizeSync(napi_env env);
    napi_value SetMousePrimaryButton(napi_env env, int32_t primaryButton, napi_value handle = nullptr);
    napi_value GetMousePrimaryButton(napi_env env, napi_value handle = nullptr);
    napi_value SetHoverScrollState(napi_env env, bool state, napi_value handle = nullptr);
    napi_value GetHoverScrollState(napi_env env, napi_value handle = nullptr);
    napi_value SetTouchpadScrollSwitch(napi_env env, bool switchFlag, napi_value handle = nullptr);
    napi_value GetTouchpadScrollSwitch(napi_env env, napi_value handle = nullptr);
    napi_value SetTouchpadScrollDirection(napi_env env, bool state, napi_value handle = nullptr);
    napi_value GetTouchpadScrollDirection(napi_env env, napi_value handle = nullptr);
    napi_value SetTouchpadTapSwitch(napi_env env, bool switchFlag, napi_value handle = nullptr);
    napi_value GetTouchpadTapSwitch(napi_env env, napi_value handle = nullptr);
    napi_value SetTouchpadPointerSpeed(napi_env env, int32_t speed, napi_value handle = nullptr);
    napi_value GetTouchpadPointerSpeed(napi_env env, napi_value handle = nullptr);
    napi_value SetTouchpadPinchSwitch(napi_env env, bool switchFlag, napi_value handle = nullptr);
    napi_value GetTouchpadPinchSwitch(napi_env env, napi_value handle = nullptr);
    napi_value SetTouchpadSwipeSwitch(napi_env env, bool switchFlag, napi_value handle = nullptr);
    napi_value GetTouchpadSwipeSwitch(napi_env env, napi_value handle = nullptr);
    napi_value SetTouchpadRightClickType(napi_env env, int32_t type, napi_value handle = nullptr);
    napi_value GetTouchpadRightClickType(napi_env env, napi_value handle = nullptr);
    napi_value SetTouchpadRotateSwitch(napi_env env, bool rotateSwitch, napi_value handle = nullptr);
    napi_value GetTouchpadRotateSwitch(napi_env env, napi_value handle = nullptr);
    napi_value SetTouchpadThreeFingersTapSwitch(napi_env env, bool switchFlag, napi_value handle = nullptr);
    napi_value GetTouchpadThreeFingersTapSwitch(napi_env env, napi_value handle = nullptr);
    
    napi_value EnableHardwareCursorStats(napi_env env, bool enable);
    napi_value GetHardwareCursorStats(napi_env env);
    napi_value SetTouchpadScrollRows(napi_env env, int32_t rows, napi_value handle = nullptr);
    napi_value GetTouchpadScrollRows(napi_env env, napi_value handle = nullptr);

private:
    napi_value SetTouchpadData(napi_env env, napi_value handle, int32_t errorCode);
    napi_value GetTouchpadBoolData(napi_env env, napi_value handle, bool data, int32_t errorCode);
    napi_value GetTouchpadInt32Data(napi_env env, napi_value handle, int32_t data, int32_t errorCode);
};
} // namespace MMI
} // namespace OHOS
#endif // JS_POINTER_MANAGER_H