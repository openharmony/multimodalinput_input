/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef EVENT_DUMP_H
#define EVENT_DUMP_H

#include "singleton.h"

#include "define_multimodal.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class EventDump final {
    DECLARE_DELAYED_SINGLETON(EventDump);
public:
    DISALLOW_COPY_AND_MOVE(EventDump);
    void ParseCommand(int32_t fd, const std::vector<std::string> &args);
    void DumpEventHelp(int32_t fd, const std::vector<std::string> &args);
    void DumpHelp(int32_t fd);
    void CheckCount(int32_t fd, const std::vector<std::string> &args, int32_t &count);
};

#define MMIEventDump ::OHOS::DelayedSingleton<EventDump>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // EVENT_DUMP_H