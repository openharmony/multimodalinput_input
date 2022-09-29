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

#include "i_input_event_consumer.h"

namespace OHOS {
namespace MMI {
using MapFun = std::map<std::string, std::function<int64_t()>>;


class InputMonitor : public IInputEventConsumer,
                     public std::enable_shared_from_this<InputMonitor> {
public:
    InputMonitor() = default;
    DISALLOW_COPY_AND_MOVE(InputMonitor);
    virtual ~InputMonitor() = default;

    int32_t Start();
    void Stop();
    void MarkConsumed(int32_t eventId);
    void SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback);
    void SetId(int32_t id);
    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override;

private:
    std::function<void(std::shared_ptr<PointerEvent>)> callback_;
    int32_t id_ { -1 };
    int32_t monitorId_ { -1 };
    mutable bool consumed_ { false };
    mutable std::mutex mutex_;
};


class JsInputMonitor {
public:
    static void JsCallback(uv_work_t *work, int32_t status);
    JsInputMonitor(napi_env jsEnv, const std::string &typeName, napi_value callback, int32_t id);
    ~JsInputMonitor();

    int32_t Start();
    void Stop();
    void MarkConsumed(const int32_t eventId);
    int32_t IsMatch(const napi_env jsEnv, napi_value callback);
    int32_t IsMatch(napi_env jsEnv);
    int32_t GetId() const;
    void OnPointerEventInJsThread(const std::string &typeName);
    void OnPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent);
    std::string GetTypeName() const;
private:
    void SetCallback(napi_value callback);
    int32_t TransformPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    std::string GetAction(int32_t action) const;
    int32_t GetJsPointerItem(const PointerEvent::PointerItem &item, napi_value value) const;
    int32_t TransformTsActionValue(int32_t pointerAction);
    int32_t TransformMousePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    int32_t GetMousePointerItem(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result);
    bool SetMouseProperty(const std::shared_ptr<PointerEvent> pointerEvent,
        const PointerEvent::PointerItem& item, napi_value result);
    bool GetAxesValue(const std::shared_ptr<PointerEvent> pointerEvent, napi_value element);
    bool GetPressedKeys(const std::vector<int32_t>& pressedKeys, napi_value result);
    bool GetPressedButtons(const std::set<int32_t>& pressedButtons, napi_value result);
    bool HasKeyCode(const std::vector<int32_t>& pressedKeys, int32_t keyCode);
    bool GetPressedKey(const std::vector<int32_t>& pressedKeys, napi_value result);
    MapFun GetFuns(const std::shared_ptr<PointerEvent> pointerEvent, const PointerEvent::PointerItem& item);
private:
    std::shared_ptr<InputMonitor> monitor_ { nullptr };
    std::queue<std::shared_ptr<PointerEvent>> evQueue_;
    napi_ref receiver_ { nullptr };
    napi_env jsEnv_ { nullptr };
    std::string typeName_;
    int32_t monitorId_ { 0 };
    int32_t jsTaskNum_ = { 0 };
    bool isMonitoring_ = { false };
    std::mutex mutex_;
};
} // namespace MMI
} // namespace OHOS
#endif // JS_INPUT_MONITOR_H
