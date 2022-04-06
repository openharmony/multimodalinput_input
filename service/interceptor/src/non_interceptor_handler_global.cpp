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

#include "non_interceptor_handler_global.h"

#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "NonInterceptorHandlerGlobal" };
} // namespace

int32_t NonInterceptorHandlerGlobal::AddInputHandler(int32_t handlerId,
    InputHandlerType handlerType, SessionPtr session)
{
    CALL_LOG_ENTER;
    return RET_ERR;
}

void NonInterceptorHandlerGlobal::RemoveInputHandler(int32_t handlerId,
    InputHandlerType handlerType, SessionPtr session)
{
    CALL_LOG_ENTER;
    return;
}

bool NonInterceptorHandlerGlobal::HandleEvent(std::shared_ptr<KeyEvent> KeyEvent)
{
    CALL_LOG_ENTER;
    return false;
}

bool NonInterceptorHandlerGlobal::HandleEvent(std::shared_ptr<PointerEvent> PointerEvent)
{
    CALL_LOG_ENTER;
    return false;
}

std::shared_ptr<IInterceptorHandlerGlobal> IInterceptorHandlerGlobal::GetInstance()
{
    if (interceptorHdlGPtr_ == nullptr) {
        interceptorHdlGPtr_ = std::make_shared<NonInterceptorHandlerGlobal>();
    }
    return interceptorHdlGPtr_;
}
} // namespace MMI
} // namespace OHOS
