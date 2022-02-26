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
#ifndef SAFE_KEEPER_H
#define SAFE_KEEPER_H

#include <mutex>
#include <vector>
#include "libmmi_util.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
using SafeCallbackFun = std::function<void(int32_t, uint64_t, const std::string&)>;
class SafeKeeper : public DelayedSingleton<SafeKeeper> {
public:
    SafeKeeper();
    virtual ~SafeKeeper();

    void Init(SafeCallbackFun fun);
    bool RegisterEvent(uint64_t tid, const std::string& remark);
    void ClearAll();
    void ReportHealthStatus(uint64_t tid);
    void ProcessEvents();

protected:
    struct SafeEvent {
        uint64_t tid;
        int64_t lastTime;
        std::string remark;
    };
    typedef std::vector<SafeEvent> SafeEventList;

    bool IsExist(uint64_t tid) const
    {
        for (const auto &item : dList_) {
            if (item.tid == tid)
                return true;
        }
        return false;
    }
    SafeEvent *GetEvent(uint64_t tid)
    {
        for (auto& it : dList_) {
            if (it.tid == tid)
                return &it;
        }
        return nullptr;
    }
    int64_t GetCurMillisTime() const
    {
        auto curSysTime = GetSysClockTime() / 1000;
        return curSysTime;
    }

protected:
    std::mutex mtx_;
    SafeEventList dList_;
    SafeCallbackFun cbFun_;
};
} // namespace MMI
} // namespace OHOS
#define SafeKpr OHOS::MMI::SafeKeeper::GetInstance()
#endif // SAFE_KEEPER_H