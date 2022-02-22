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

#ifndef REGISTER_EVENTHANDLE_MANAGER_H
#define REGISTER_EVENTHANDLE_MANAGER_H

#include <mutex>
#include <map>
#include <iostream>
#include "libmmi_util.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class RegisterEventHandleManager : public DelayedSingleton<RegisterEventHandleManager> {
public:
    RegisterEventHandleManager();
    ~RegisterEventHandleManager();

    int32_t RegisterEvent(MmiMessageId messageId, int32_t fd);

    int32_t UnregisterEventHandleManager(MmiMessageId messageId, int32_t fd);

    void UnregisterEventHandleBySocketFd(int32_t fd);

    void FindSocketFds(const MmiMessageId messageId, std::vector<int32_t>& fds);

    void PrintfMap();
    void Dump(int32_t fd);
    void Clear();

private:
    void RegisterEventHandleByIdMsage(const MmiMessageId idMsgBegin, const MmiMessageId idMsgEnd, const int32_t fd);
    void UnregisterEventHandleByIdMsage(const MmiMessageId idMsgBegin, const MmiMessageId idMsgEnd, const int32_t fd);

private:
    std::mutex mu_;
    std::multimap<MmiMessageId, int32_t> mapRegisterManager_ = {}; // key=enum MmiMessageId : value=fd
};
} // namespace MMI
} // namespace OHOS
#define RegEventHM OHOS::MMI::RegisterEventHandleManager::GetInstance()
#endif // REGISTER_EVENTHANDLE_MANAGER_H