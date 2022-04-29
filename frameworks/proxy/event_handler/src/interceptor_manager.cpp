/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "interceptor_manager.h"

#include <cinttypes>

#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "InterceptorManager" };
constexpr int32_t SOURCETYPE_KEY = 4;
constexpr int32_t INVALID_INTERCEPTOR_ID = -1;
} // namespace

InterceptorManager::InterceptorManager() {}

int32_t InterceptorManager::AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor)
{
    CHKPR(interceptor, INVALID_INTERCEPTOR_ID);
    InterceptorItem interceptorItem;
    interceptorItem.id_ = ++InterceptorItemId;
    interceptorItem.sourceType = SOURCETYPE_KEY;
    interceptorItem.callback_ = interceptor;
    interceptor_.push_back(interceptorItem);
    MMIEventHdl.AddInterceptor(interceptorItem.sourceType, interceptorItem.id_);
    MMI_HILOGD("Add AddInterceptor KeyEvent to InterceptorManager success");
    return interceptorItem.id_;
}

void InterceptorManager::RemoveInterceptor(int32_t interceptorId)
{
    if (interceptorId <= 0) {
        MMI_HILOGE("interceptorId invalid");
        return;
    }
    InterceptorItem interceptorItem;
    interceptorItem.id_ = interceptorId;
    auto iter = std::find(interceptor_.begin(), interceptor_.end(), interceptorItem);
    if (iter == interceptor_.end()) {
        MMI_HILOGE("InterceptorItem does not exist");
        return;
    }
    iter = interceptor_.erase(iter);
    MMIEventHdl.RemoveInterceptor(interceptorItem.id_);
    MMI_HILOGD("InterceptorItem id:%{public}d removed success", interceptorId);
}

int32_t InterceptorManager::OnKeyEvent(std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPR(keyEvent, ERROR_NULL_POINTER);
    BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::TRACE_STOP, BytraceAdapter::KEY_INTERCEPT_EVENT);
    for (auto &item : interceptor_) {
        if (item.sourceType == SOURCETYPE_KEY) {
            MMI_HILOGD("interceptor callback execute");
            item.callback_(keyEvent);
        }
    }
    return MMI_STANDARD_EVENT_SUCCESS;
}
} // namespace MMI
} // namespace OHOS