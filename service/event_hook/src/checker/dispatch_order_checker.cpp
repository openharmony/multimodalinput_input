/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dispatch_order_checker.h"

#include "define_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DispatchOrderChecker"

namespace OHOS {
namespace MMI {
bool DispatchOrderChecker::CheckOrder(int32_t eventId)
{
    MMI_HILOGD("Check lastId:%{public}d, eventId:%{public}d", lastDispatchedEventId_.load(), eventId);
    return lastDispatchedEventId_.load() < eventId;
}

void DispatchOrderChecker::UpdateEvent(int32_t eventId)
{
    MMI_HILOGD("Store lastId:%{public}d, eventId:%{public}d", lastDispatchedEventId_.load(), eventId);
    lastDispatchedEventId_.store(eventId);
}
} // namespace MMI
} // namespace OHOS