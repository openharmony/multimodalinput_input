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

#ifndef EVENT_DUMP_H
#define EVENT_DUMP_H

#include "nocopyable.h"
#include "singleton.h"

#include "libmmi_util.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class EventDump : public DelayedSingleton<EventDump> {
public:
    EventDump() = default;
    DISALLOW_COPY_AND_MOVE(EventDump);
    void Init(UDSServer& udss);
    void Dump(int32_t fd = 0);
    void TestDump();
    void InsertDumpInfo(const std::string& str);
    void InsertFormat(std::string str, ...);

private:
    std::mutex mu_;
    std::vector<std::string> dumpInfo_;
    UDSServer* udsServer_ = nullptr;
};

#define MMIEventDump EventDump::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // EVENT_DUMP_H