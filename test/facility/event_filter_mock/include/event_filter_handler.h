/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MMI_EVENT_FILTER_HANDLER_MOCK_H
#define MMI_EVENT_FILTER_HANDLER_MOCK_H
#include <cstdint>
#include <gmock/gmock.h>
#include "ievent_filter.h"

namespace OHOS {
namespace MMI {
class IEventFilterHandler {
public:
    IEventFilterHandler() = default;
    virtual ~IEventFilterHandler() = default;

    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter,
        int32_t filterId, int32_t priority, uint32_t deviceTags, int32_t clientPid) = 0;
    virtual int32_t RemoveInputEventFilter(int32_t filterId, int32_t clientPid) = 0;
};

class EventFilterHandler final : public IEventFilterHandler {
public:
    EventFilterHandler() = default;
    ~EventFilterHandler() override = default;

    MOCK_METHOD(int32_t, AddInputEventFilter, (sptr<IEventFilter>, int32_t, int32_t, uint32_t, int32_t));
    MOCK_METHOD(int32_t, RemoveInputEventFilter, (int32_t, int32_t));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_EVENT_FILTER_HANDLER_MOCK_H