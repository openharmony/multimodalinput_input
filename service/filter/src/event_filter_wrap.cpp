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

#include "event_filter_wrap.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventFilterWrap" };
} // namespace

EventFilterWrap::EventFilterWrap()
{
    MMI_LOGD("enter");
}

EventFilterWrap::~EventFilterWrap()
{
    MMI_LOGD("enter");
}

int32_t EventFilterWrap::AddInputEventFilter(sptr<IEventFilter> filter)
{
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> guard(lockInputEventFilter_);
    filter_ = filter;
    MMI_LOGD("leave");
    return RET_OK;
}

bool EventFilterWrap::HandlePointerEventFilter(std::shared_ptr<PointerEvent> point)
{
    MMI_LOGD("enter");
    CHKPF(point);
    std::lock_guard<std::mutex> guard(lockInputEventFilter_);
    CHKPF(filter_);
    if (filter_->HandlePointerEvent(point)) {
        MMI_LOGD("call HandlePointerEvent return true");
        return true;
    }
    MMI_LOGD("leave");
    return false;
}
} // namespace MMI
} // namespace OHOS
