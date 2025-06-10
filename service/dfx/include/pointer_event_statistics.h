/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef POINTER_EVENT_STATISTICS_H
#define POINTER_EVENT_STATISTICS_H

namespace OHOS {
namespace MMI {
class PointerEventStatistics {
public:
    enum ExitPoint : int32_t {
        FILTER_CONSUME = 0,
        INTERCEPT_CONSUME,
        STYLUS_INTERRUPT_TOUCH,
        FOLD_INTERRUPT_TOUCH,
        ANCO_CONSUME,
        TRANSFORM_CANCEL,
        DISPATCH,
        AIBASE_GESTURE,
        MULTI_FINGER_GESTURE,
        MAX
    };

    enum ErrnoCode : int32_t {
        DISPLAY_NOT_FOUND = 65470476,
        WINDOW_NOT_FOUND = 65470477,
        SESSION_NOT_FOUND = 65470478
    };

    PointerEventStatistics()
    {
        std::fill(std::begin(counters_), std::end(counters_), 0);
    }

    void AddExitPoint(ExitPoint exitPoint)
    {
        counters_[static_cast<int>(exitPoint)]++;
        callCount_++;
    }

    void ClearStats()
    {
        std::fill(std::begin(counters_), std::end(counters_), 0);
        callCount_ = 0;
    }

    int32_t GetCallCount()
    {
        return callCount_;
    }

    int counters_[static_cast<int>(ExitPoint::MAX)];
    int32_t callCount_{0};
}; // class PointerEventStatistics
} // namespace MMI
} // namespace OHOS

#endif // POINTER_EVENT_STATISTICS_H
