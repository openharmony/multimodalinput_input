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

#ifndef INPUT_INTERCEPTOR_MANAGER_H
#define INPUT_INTERCEPTOR_MANAGER_H

#include <memory>

#include "singleton.h"

#include "input_handler_manager.h"
#include "input_handler_type.h"

namespace OHOS {
namespace MMI {
class InputInterceptorManager final : public InputHandlerManager {
    DECLARE_DELAYED_SINGLETON(InputInterceptorManager);
public:
    DISALLOW_COPY_AND_MOVE(InputInterceptorManager);
    int32_t AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor, HandleEventType eventType);
    int32_t AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags);
    int32_t RemoveInterceptor(int32_t interceptorId);
    InputHandlerType GetHandlerType() const override;
};

inline InputHandlerType InputInterceptorManager::GetHandlerType() const
{
    return InputHandlerType::INTERCEPTOR;
}

#define InputInterMgr ::OHOS::DelayedSingleton<InputInterceptorManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_INTERCEPTOR_MANAGER_H
