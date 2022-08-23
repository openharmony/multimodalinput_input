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

#include "axis_event.h"

#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "AxisEvent" };
} // namespace
std::shared_ptr<AxisEvent> AxisEvent::from(std::shared_ptr<InputEvent> inputEvent)
{
    return nullptr;
}

AxisEvent::AxisEvent(int32_t eventType) : InputEvent(eventType) {}

AxisEvent::~AxisEvent() {}

std::shared_ptr<AxisEvent> AxisEvent::Create()
{
    auto event = std::shared_ptr<AxisEvent>(new (std::nothrow) AxisEvent(InputEvent::EVENT_TYPE_AXIS));
    CHKPP(event);
    return event;
}

int32_t AxisEvent::GetAxisAction()
{
    return 0;
}

void AxisEvent::SetAxisAction(int32_t axisAction) {}

int32_t AxisEvent::GetAxisType() const
{
    return 0;
}

void AxisEvent::SetAxisType(int32_t axisType) {}

int32_t AxisEvent::GetAxisValue() const
{
    return 0;
}

void AxisEvent::SetAxisValue(int32_t axisValue) {}
} // namespace MMI
} // namespace OHOS
