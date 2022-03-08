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
#include <mutex>
#include <queue>
#include <uv.h>
#include "i_input_event_consumer.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace MMI {
class InputMonitor : public IInputEventConsumer,
                     public std::enable_shared_from_this<InputMonitor> {
public:
    InputMonitor() = default;
    virtual ~InputMonitor() = default;

    bool Start();

    void Stop();

    void MarkConsumed(int32_t eventId);

    void SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback);

    void SetId(int32_t id);

    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override;

    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;

    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override;

private:
    InputMonitor(const InputMonitor&) = delete;

    InputMonitor(InputMonitor&&) = delete;

    InputMonitor& operator=(const InputMonitor&) = delete;

private:
    int32_t id_ {-1};
    mutable std::mutex mutex_;
    int32_t monitorId_ {-1};
    std::function<void(std::shared_ptr<PointerEvent>)> callback_;
    mutable bool consumed_ {false};
};


class JsInputMonitor {
public:
    JsInputMonitor(napi_env jsEnv, napi_value callback, int32_t id);

    ~JsInputMonitor();

    bool Start();

    void Stop();

    void MarkConsumed(const int32_t eventId);

    int32_t IsMatch(const napi_env jsEnv, napi_value callback);

    int32_t IsMatch(napi_env jsEnv);

    int32_t GetId() const;

    void OnPointerEventInJsThread();

    void OnPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent);
    
    static void JsCallback(uv_work_t *work, int32_t status);
private:

    void SetCallback(napi_value callback);

    int32_t TransformPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, napi_value result);

    std::string GetAction(int32_t action) const;

    int32_t GetJsPointerItem(const PointerEvent::PointerItem &item, napi_value value) const;

private:
    std::shared_ptr<InputMonitor> monitor_ {nullptr};
    napi_ref receiver_ {nullptr};
    napi_env jsEnv_ {nullptr};
    int32_t id_ = 0;
    bool isMonitoring_ = false;
    std::queue<std::shared_ptr<PointerEvent>> evQueue_;
    std::mutex mutex_;
    int32_t jsTaskNum_ = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // JS_INPUT_MONITOR_H
