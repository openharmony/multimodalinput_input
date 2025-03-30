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
        const std::string eventType = GetEventTypeString(llParam1_);
        if ((ullCost > uiTime_) && strReason_.size() > 0 && strOutput_.size() > 0) {
            if ((llParam1_ != 0 || llParam2_ != 0) && (!eventType.empty())) {
                MMI_HILOGD("Time cost overtime (%{public}" PRId64 ",(us)>%{public}" PRId64
                    "(us)) when Reason:%{public}s,chk:%{public}s,"
                    "paramType:%{public}s, param2:%{public}" PRId64 "",
                    ullCost, uiTime_, strReason_.c_str(), strOutput_.c_str(), eventType.c_str(), llParam2_);
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

    const std::string GetEventTypeString(int64_t key)
    {
        switch (key) {
            case 1: /* 1: device_added */
                return "device_added";
            case 2: /* 2: device_removed */
                return "device_removed";
            case 300: /* 300: keyboard_key */
                return "keyboard_key";
            case 400: /* 400: pointer_monitor */
                return "pointer_monitor";
            case 401: /* 401: pointer_monitor_absolute */
                return "pointer_monitor_absolute";
            case 402: /* 402: pointer_button */
                return "pointer_button";
            case 403: /* 403: pointer_axis */
                return "pointer_axis";
            case 500: /* 500: touch_down */
                return "touch_down";
            case 501: /* 501: touch_up */
                return "touch_up";
            case 502: /* 502: touch_monitor */
                return "touch_monitor";
            case 600: /* 600: tablet_tool_axis */
                return "tablet_tool_axis";
            case 800: /* 800: gesture_swipe_begin */
                return "gesture_swipe_begin";
            case 801: /* 801: gesture_swipe_update */
                return "gesture_swipe_update";
            case 802: /* 802: gesturn_swipe_end */
                return "gesturn_swipe_end";
            case 803: /* 803: gesturn_pinch_begin */
                return "gesturn_pinch_begin";
            case 804: /* 804: gesturn_pinch_update */
                return "gesturn_pinch_update";
            case 805: /* 805: gesturn_pinch_end */
                return "gesturn_pinch_end";
            default:
                return "";
        }
    }

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
