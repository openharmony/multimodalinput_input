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

#ifndef TIME_COST_CHK_H
#define TIME_COST_CHK_H

#include <cinttypes>
#include <map>

#include "nocopyable.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TimeCostChk"

namespace OHOS {
namespace MMI {
inline constexpr int64_t MAX_INPUT_EVENT_TIME { 1000 };
inline constexpr int64_t MAX_OVER_TIME { 300 };
static std::map<int32_t, std::string> paramType = {
    { 1, "device_added" },
    { 2, "device_removed" },
    { 300, "keyboard_key" },
    { 400, "pointer_monitor" },
    { 401, "pointer_monitor_absolute" },
    { 402, "pointer_button" },
    { 403, "pointer_axis" },
    { 500, "touch_down" },
    { 501, "touch_up" },
    { 502, "touch_monitor" },
    { 600, "tablet_tool_axis" },
    { 800, "gesture_swipe_begin" },
    { 801, "gesture_swipe_update" },
    { 802, "gesturn_swipe_end" },
    { 803, "gesturn_pinch_begin" },
    { 804, "gesturn_pinch_update" },
    { 805, "gesturn_pinch_end" },
};
template <class T> class TimeCostChk {
public:
    TimeCostChk(const std::string &strReason, const std::string &strOutputStr, int64_t tmChk, T llParam1,
        int64_t llParam2 = 0)
        : beginTime_(std::chrono::high_resolution_clock::now()),
          strOutput_(strOutputStr),
          strReason_(strReason),
          uiTime_(tmChk),
          llParam1_(static_cast<int64_t>(llParam1)),
          llParam2_(llParam2)
    {}

    ~TimeCostChk(void)
    {
        int64_t ullCost = GetElapsed_micro();
        if ((ullCost > uiTime_) && strReason_.size() > 0 && strOutput_.size() > 0) {
            if ((llParam1_ != 0 || llParam2_ != 0) && (paramType.find(llParam1_) != paramType.end())) {
                MMI_HILOGD("Time cost overtime (%{public}" PRId64 ",(us)>%{public}" PRId64
                    "(us)) when Reason:%{public}s,chk:%{public}s,"
                    "paramType:%{public}s, param2:%{public}" PRId64 "",
                    ullCost, uiTime_, strReason_.c_str(), strOutput_.c_str(), paramType[llParam1_].data(), llParam2_);
            } else {
                MMI_HILOGD("Overtime(%{public}" PRId64 ",(us)>%{public}" PRId64
                    "(us)) when Reason:%{public}s,chk:%{public}s",
                    ullCost, uiTime_, strReason_.c_str(), strOutput_.c_str());
            }
        }
    }

    DISALLOW_COPY_AND_MOVE(TimeCostChk);

    int64_t GetElapsed_micro() const
    {
        int64_t tm64Cost = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::high_resolution_clock::now() - beginTime_
                            ).count();
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
