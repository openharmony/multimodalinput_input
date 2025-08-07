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

#ifndef MMI_EVENT_INTERCEPTOR_HANDLER_MOCK_H
#define MMI_EVENT_INTERCEPTOR_HANDLER_MOCK_H
#include <cstdint>
#include <gmock/gmock.h>
#include "input_handler_type.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
class IEventInterceptorHandler {
public:
    IEventInterceptorHandler() = default;
    virtual ~IEventInterceptorHandler() = default;

    virtual int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags, SessionPtr session) = 0;
    virtual void RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags, SessionPtr session) = 0;
};

class EventInterceptorHandler : public IEventInterceptorHandler {
public:
    EventInterceptorHandler() = default;
    virtual ~EventInterceptorHandler() override = default;

    MOCK_METHOD(int32_t, AddInputHandler, (InputHandlerType, HandleEventType, int32_t, uint32_t, SessionPtr));
    MOCK_METHOD(void, RemoveInputHandler, (InputHandlerType, HandleEventType, int32_t, uint32_t, SessionPtr));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_EVENT_INTERCEPTOR_HANDLER_MOCK_H