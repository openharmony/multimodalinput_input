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

#ifndef TIME_COST_CHK_H
#define TIME_COST_CHK_H

#include <cinttypes>

#include "nocopyable.h"

namespace OHOS {
namespace MMI {
inline constexpr int64_t MAX_INPUT_EVENT_TIME = 1000;
inline constexpr int64_t MAX_OVER_TIME = 300;
template<class T>
class TimeCostChk {
    static inline constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "TimeCostChk" };
public:
    TimeCostChk(const std::string& strReason, const std::string& strOutputStr, int64_t tmChk, T llParam1,
                int64_t llParam2 = 0)
        : beginTime_(std::chrono::high_resolution_clock::now()),
          strOutput_(strOutputStr),
          strReason_(strReason),
          uiTime_(tmChk),
          llParam1_(static_cast<int64_t>(llParam1)),
          llParam2_(llParam2) {}

    ~TimeCostChk(void)
    {
        int64_t ullCost = GetElapsed_micro();
        if ((ullCost > uiTime_) && strReason_.size() > 0 && strOutput_.size() > 0) {
            if (llParam1_ != 0 || llParam2_ != 0) {
                MMI_HILOGW("Time cost overtime (%{public}" PRId64 ",(us)>%{public}" PRId64
                         "(us)) when Reason:%{public}s,chk:%{public}s,"
                         "param1:%{public}" PRId64 ",param2:%{public}" PRId64 "",
                         ullCost, uiTime_, strReason_.c_str(), strOutput_.c_str(), llParam1_, llParam2_);
            } else {
                MMI_HILOGW("Overtime(%{public}" PRId64 ",(us)>%{public}" PRId64
                         "(us)) when Reason:%{public}s,chk:%{public}s",
                         ullCost, uiTime_, strReason_.c_str(), strOutput_.c_str());
            }
        }
    }

    DISALLOW_COPY_AND_MOVE(TimeCostChk);

    int64_t GetElapsed_micro() const
    {
        int64_t tm64Cost = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - beginTime_).count();
        return tm64Cost;
    }

private:
    const std::chrono::time_point<std::chrono::high_resolution_clock> beginTime_;
    const std::string strOutput_ = "";
    const std::string strReason_ = "";
    const int64_t uiTime_ { 0 };
    const int64_t llParam1_ { 0 };
    const int64_t llParam2_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // TIME_COST_CHK_H