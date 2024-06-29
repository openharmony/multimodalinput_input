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

#ifndef EVENT_FILTER_SERVICE_H
#define EVENT_FILTER_SERVICE_H

#include <list>

#include "iremote_object.h"
#include "nocopyable.h"

#include "event_filter_stub.h"
#include "i_input_event_filter.h"

namespace OHOS {
namespace MMI {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class EventFilterService final : public EventFilterStub {
public:
    static int32_t GetNextId();
    EventFilterService(std::shared_ptr<IInputEventFilter> filter) : filter_(filter) {}
    DISALLOW_COPY_AND_MOVE(EventFilterService);
    ~EventFilterService() override = default;
    bool HandleKeyEvent(const std::shared_ptr<KeyEvent> event) override;
    bool HandlePointerEvent(const std::shared_ptr<PointerEvent> event) override;
private:
    const std::shared_ptr<IInputEventFilter> filter_;
    static inline int32_t filterIdSeed_ { 0 };
    static inline std::mutex mutex_;
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_FILTER_SERVICE_H