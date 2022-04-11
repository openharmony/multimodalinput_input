/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "i_input_interceptor_manager.h"
#include "input_handler_type.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "IInputInterceptorManager" };
} // namespace

int32_t IInputInterceptorManager::AddInterceptor(std::shared_ptr<IInputEventConsumer> interceptor)
{
    CALL_LOG_ENTER;
    return INVALID_HANDLER_ID;
}

void IInputInterceptorManager::RemoveInterceptor(int32_t interceptorId)
{
    MMI_HILOGD("Interceptor is:%{public}d", interceptorId);
    return;
}

std::shared_ptr<IInputInterceptorManager> IInputInterceptorManager::GetInstance()
{
    if (inputMgrPtr_ == nullptr) {
        inputMgrPtr_ = std::make_shared<IInputInterceptorManager>();
    }
    return inputMgrPtr_;
}
} // namespace MMI
} // namespace OHOS
