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

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InputInterceptorManager" };
} // namespace

int32_t InputInterceptorManager::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor)
{
    if (interceptor == nullptr) {
        MMI_HILOGE("No interceptor was specified.");
        return INVALID_HANDLER_ID;
    }
    return InputHandlerManager::GetInstance().AddHandler(InputHandlerType::INTERCEPTOR, interceptor);
}

void InputInterceptorManager::RemoveInterceptor(int32_t interceptorId)
{
    InputHandlerManager::GetInstance().RemoveHandler(interceptorId, InputHandlerType::INTERCEPTOR);
}

std::shared_ptr<IInputInterceptorManager> IInputInterceptorManager::GetInstance()
{
    if (inputMgrPtr_ == nullptr) {
        inputMgrPtr_ = std::make_shared<InputInterceptorManager>();
    }
    return inputMgrPtr_;
}
} // namespace MMI
} // namespace OHOS
