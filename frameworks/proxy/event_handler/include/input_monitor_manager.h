/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef INPUT_MONITOR_MANAGER_H
#define INPUT_MONITOR_MANAGER_H
#include <memory>
#include "input_handler_type.h"
#include "i_input_event_consumer.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class InputMonitorManager {
public:
    int32_t AddMonitor(std::shared_ptr<IInputEventConsumer> monitor);
    void RemoveMonitor(int32_t monitorId);
    void MarkConsumed(int32_t monitorId, int32_t eventId);

public:
    static bool IsValidMonitorId(int32_t monitorId);
};

inline bool InputMonitorManager::IsValidMonitorId(int32_t monitorId)
{
    return IsValidHandlerId(monitorId);
}
} // namespace MMI
} // namespace OHOS
#endif // INPUT_MONITOR_MANAGER_H