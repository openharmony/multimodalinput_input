/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef WATCHDOG_TASK_H
#define WATCHDOG_TASK_H

#include "singleton.h"

namespace OHOS {
namespace MMI {
class WatchdogTask {
    DECLARE_DELAYED_SINGLETON(WatchdogTask);

public:
    DISALLOW_COPY_AND_MOVE(WatchdogTask);
    bool IsNumberic(const std::string &str);
    bool IsProcessDebug(int32_t pid);
    std::string GetSelfProcName();
    std::string GetFirstLine(const std::string& path);
    std::string GetProcessNameFromProcCmdline(int32_t pid);
    std::string GetBlockDescription(uint64_t interval);
    void SendEvent(const std::string &msg, const std::string &eventName);
};
#define WATCHDOG_TASK ::OHOS::DelayedSingleton<WatchdogTask>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // WATCHDOG_TASK_H