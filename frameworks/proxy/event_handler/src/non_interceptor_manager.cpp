/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "non_interceptor_manager.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "NonInterceptorManager" };
} // namespace

int32_t NonInterceptorManager::AddInterceptor(int32_t sourceType,
    std::function<void(std::shared_ptr<PointerEvent>)> interceptor)
{
    CALL_LOG_ENTER;
    return -1;
}

int32_t NonInterceptorManager::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    CALL_LOG_ENTER;
    return -1;
}

void NonInterceptorManager::RemoveInterceptor(int32_t interceptorId)
{
    MMI_HILOGD("Interceptor is:%{public}d", interceptorId);
    return;
}

int32_t NonInterceptorManager::OnPointerEvent(std::shared_ptr<PointerEvent> pointerEvent, int32_t id)
{
    CALL_LOG_ENTER;
    return -1;
}

int32_t NonInterceptorManager::OnKeyEvent(std::shared_ptr<KeyEvent> pointerEvent)
{
    CALL_LOG_ENTER;
    return -1;
}

std::shared_ptr<IInterceptorManager> IInterceptorManager::GetInstance()
{
    if (interceptorMgrPtr_ == nullptr) {
        interceptorMgrPtr_ = std::make_shared<NonInterceptorManager>();
    }
    return interceptorMgrPtr_;
}
} // namespace MMI
} // namespace OHOS