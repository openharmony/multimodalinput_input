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

#include "event_filter_service.h"

#include <cstring>

#include <sys/types.h>
#include <unistd.h>

#include "string_ex.h"

#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventFilterService" };
} // namespace

EventFilterService::EventFilterService()
{
    CALL_DEBUG_ENTER;
}

EventFilterService::~EventFilterService()
{
    CALL_DEBUG_ENTER;
}

void EventFilterService::SetPointerEventPtr(std::function<bool(std::shared_ptr<PointerEvent>)> pointerFilter)
{
    pointerFilter_ = pointerFilter;
}

bool EventFilterService::HandlePointerEvent(const std::shared_ptr<PointerEvent> event)
{
    CHKPF(pointerFilter_);
    return pointerFilter_(event);
}
} // namespace MMI
} // namespace OHOS
