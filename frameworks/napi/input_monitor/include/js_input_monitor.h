/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef JS_INPUT_MONITOR_H
#define JS_INPUT_MONITOR_H

#include <cinttypes>
#include <map>
#include <mutex>
#include <queue>
#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "nocopyable.h"
#include "util_napi.h"
#include "window_info.h"

#include "i_input_event_consumer.h"
#include "js_touch_event.h"
#include "js_joystick_event.h"

namespace OHOS {
namespace MMI {
using MapFun = std::map<std::string, std::function<int64_t()>>;

class InputMonitor final : public IInputEventConsumer, public std::enable_shared_from_this<InputMonitor> {
public:
    InputMonitor() = default;
    DISALLOW_COPY_AND_MOVE(InputMonitor);
    ~InputMonitor() override = default;

    int32_t Start();
    void Stop();
    void MarkConsumed(int32_t eventId);
    void SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback);
    void SetId(int32_t id);
    void SetFingers(int32_t fingers);
    void SetHotRectArea(std::vector<Rect> hotRectArea);
    std::vector<Rect> GetHotRectArea();
    void SetRectTotal(uint32_t rectTotal);
    uint32_t GetRectTotal();
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override;
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override;
    std::string GetTypeName() const;
    void SetTypeName(const std::string &typeName);
private:
    bool IsGestureEvent(std::shared_ptr<PointerEvent> pointerEvent) const;
    void SetConsumeState(std::shared_ptr<PointerEvent> pointerEvent) const;

private:
    std::function<void(std::shared_ptr<PointerEvent>)> callback_;
    int32_t id_ { -1 };
    int32_t monitorId_ { -1 };
    int32_t fingers_ { 0 };
    std::vector<Rect> hotRectArea_;
    uint32_t rectTotal_ { 0 };
    mutable bool consumed_ { false };
    mutable std::mutex mutex_;
    mutable int32_t flowCtrl_ { 0 };
    std::string typeName_;
};

class JsInputMonitor final {
public:
    static void JsCallback(uv_work_t *work, int32_t status);
    JsInputMonitor(napi_env jsEnv, const std::string &typeName, std::vector<Rect> hotRectArea,
        int32_t rectTotal, napi_value callback, int32_t id, int32_t fingers);
    JsInputMonitor(napi_env jsEnv, const std::string &typeName, napi_value callback, int32_t id, int32_t fingers);
    ~JsInputMonitor();

    int32_t Start();
    void Stop();
    void MarkConsumed(const int32_t eventId);
    int32_t IsMatch(const napi_env jsEnv, napi_value callback);
    int32_t IsMatch(napi_env jsEnv);
    int32_t GetId() const;
    int32_t GetFingers() const;
    void OnPointerEventInJsThread(const std::string &typeName, const int32_t fingers);
    void CheckConsumed(bool retValue, std::shared_ptr<PointerEvent> pointerEvent);
    void OnPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent);
    std::string GetTypeName() const;
    bool IsLocaledWithinRect(napi_env env, napi_value napiPointer, uint32_t rectTotal, std::vector<Rect> hotRectArea);
private:
    void SetCallback(napi_value callback);
    MapFun GetInputEventFunc(const std::shared_ptr<InputEvent> inputEvent);
    int32_t SetInputEventProperty(const std::shared_ptr<InputEvent> inputEvent, napi_value result);
    int32_t TransformPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    int32_t GetAction(int32_t action) const;
    int32_t GetSourceType(int32_t sourceType) const;
    int32_t GetPinchAction(int32_t action) const;
    int32_t GetSwipeAction(int32_t action) const;
    int32_t GetRotateAction(int32_t action) const;
    int32_t GetMultiTapAction(int32_t action) const;
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    int32_t GetFingerprintAction(int32_t action) const;
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
    int32_t GetJsPointerItem(const PointerEvent::PointerItem &item, napi_value value) const;
    int32_t TransformTsActionValue(int32_t pointerAction);
    int32_t TransformMousePointerEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    int32_t TransformPinchEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    int32_t TransformSwipeEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    int32_t TransformRotateEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    int32_t TransformMultiTapEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    int32_t TransformSwipeInwardEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    int32_t TransformJoystickPointerEvent(std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
#ifdef OHOS_BUILD_ENABLE_FINGERPRINT
    int32_t TransformFingerprintEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
#endif // OHOS_BUILD_ENABLE_FINGERPRINT
    int32_t GetMousePointerItem(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    std::optional<int32_t> GetJoystickAction(int32_t action);
    int32_t GetJoystickButton(int32_t button);
    int32_t GetJoystickPointerItem(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    bool SetMouseProperty(const std::shared_ptr<PointerEvent> pointerEvent,
        const PointerEvent::PointerItem& item, napi_value result);
    bool GetAxesValue(const std::shared_ptr<PointerEvent> pointerEvent, napi_value element);
    bool GetPressedKeys(const std::vector<int32_t>& pressedKeys, napi_value result);
    bool GetJoystickPressedButtons(const std::set<int32_t>& pressedButtons, napi_value result);
    bool GetPressedButtons(const std::set<int32_t>& pressedButtons, napi_value result);
    bool HasKeyCode(const std::vector<int32_t>& pressedKeys, int32_t keyCode);
    bool GetPressedKey(const std::vector<int32_t>& pressedKeys, napi_value result);
    bool IsPinch(std::shared_ptr<PointerEvent> pointerEvent, const int32_t fingers);
    bool IsRotate(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsThreeFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsFourFingersSwipe(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsBeginAndEnd(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsThreeFingersTap(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsSwipeInward(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsJoystick(std::shared_ptr<PointerEvent> pointerEvent);
    bool IsFingerprint(std::shared_ptr<PointerEvent> pointerEvent);
    MapFun GetFuns(const std::shared_ptr<PointerEvent> pointerEvent, const PointerEvent::PointerItem& item);
private:
    std::shared_ptr<InputMonitor> monitor_ { nullptr };
    std::queue<std::shared_ptr<PointerEvent>> evQueue_;
    std::list<std::shared_ptr<PointerEvent>> pointerQueue_;
    napi_ref receiver_ { nullptr };
    napi_env jsEnv_ { nullptr };
    std::string typeName_;
    int32_t monitorId_ { 0 };
    int32_t fingers_ { 0 };
    bool isMonitoring_ { false };
    std::mutex mutex_;
    std::mutex resourcemutex_;
};
} // namespace MMI
} // namespace OHOS
#endif // JS_INPUT_MONITOR_H
