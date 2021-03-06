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

#ifndef OHOS_EVENTDUMP_H
#define OHOS_EVENTDUMP_H

#include "libmmi_util.h"
#include "app_register.h"
#include "c_singleton.h"

namespace OHOS {
namespace MMI {
class EventDump : public CSingleton<EventDump> {
public:
    void Init(UDSServer& udss);
    void Dump(int32_t fd);
    void TestDump();
    void InsertDumpInfo(const std::string& str);
    void InsertFormat(std::string str, ...);

private:
    std::mutex mu_;
    StringList dumpInfo_;
    UDSServer* udsServer_ = nullptr;
};
};
}
#define MMIEventDump OHOS::MMI::EventDump::GetInstance()
#endif
