/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "event_filter_wrap.h"
#include "log.h"

namespace OHOS {
namespace MMI {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventFilterWrap" };
}

EventFilterWrap::EventFilterWrap()
{
    MMI_LOGT("enter");
}

EventFilterWrap::~EventFilterWrap()
{
    MMI_LOGT("enter");
}

int32_t EventFilterWrap::AddInputEventFilter(sptr<IEventFilter> filter)
{
    MMI_LOGT("enter");
    std::lock_guard<std::mutex> guard(lockInputEventFilter_);
    filter_ = filter;

    return RET_OK;
}

bool EventFilterWrap::HandlePointerEventFilter(std::shared_ptr<PointerEvent> point)
{
    MMI_LOGT("enter");
    std::lock_guard<std::mutex> guard(lockInputEventFilter_);
    if (filter_ == nullptr) {
        MMI_LOGD("filter_ is nullptr");
        return false;
    }

    if (filter_->HandlePointerEvent(point)) {
        MMI_LOGD("call HandlePointerEvent return true");
        return true;
    }
    
    MMI_LOGT("leave");
    return false;
}
} // namespace MMI
} // namespace OHOS
