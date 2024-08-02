/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_INPUT_INTERCEPTOR_H
#define OH_INPUT_INTERCEPTOR_H

#include <mutex>

#include "i_input_event_consumer.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
typedef enum {
    INTERCEPTOR_TYPE_KEY,
    INTERCEPTOR_TYPE_POINTER
} OHInterceptorType;

class OHInputInterceptor final : public IInputEventConsumer, public std::enable_shared_from_this<OHInputInterceptor> {
public:
    OHInputInterceptor() = default;
    DISALLOW_COPY_AND_MOVE(OHInputInterceptor);
    ~OHInputInterceptor() override = default;

    int32_t Start(OHInterceptorType type);
    int32_t Stop(OHInterceptorType type);
    void SetCallback(std::function<void(std::shared_ptr<PointerEvent>)> callback);
    void SetCallback(std::function<void(std::shared_ptr<KeyEvent>)> callback);
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override;
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override;

private:
    std::function<void(std::shared_ptr<KeyEvent>)> keyCallback_;
    std::function<void(std::shared_ptr<PointerEvent>)> pointerCallback_;
    int32_t keyInterceptorId_ { -1 };
    int32_t pointerInterceptorId_ { -1 };
    mutable std::mutex mutex_;
};
}
}
#endif