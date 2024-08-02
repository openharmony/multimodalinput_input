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

#include "input_interceptor_manager.h"

#include "input_handler_manager.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputInterceptorManager"

namespace OHOS {
namespace MMI {
InputInterceptorManager::InputInterceptorManager() {}
InputInterceptorManager::~InputInterceptorManager() {}

int32_t InputInterceptorManager::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor,
    HandleEventType eventType)
{
    CHKPR(interceptor, INVALID_HANDLER_ID);
    return AddHandler(InputHandlerType::INTERCEPTOR, interceptor, eventType);
}

int32_t InputInterceptorManager::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor,
    HandleEventType eventType, int32_t priority, uint32_t deviceTags)
{
    CHKPR(interceptor, INVALID_HANDLER_ID);
    return AddHandler(InputHandlerType::INTERCEPTOR, interceptor, eventType, priority, deviceTags);
}

int32_t InputInterceptorManager::RemoveInterceptor(int32_t interceptorId)
{
    return RemoveHandler(interceptorId, InputHandlerType::INTERCEPTOR);
}
} // namespace MMI
} // namespace OHOS
