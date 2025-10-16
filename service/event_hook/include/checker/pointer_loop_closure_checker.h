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

#ifndef POINTER_LOOP_CLOSURE_CHECKER_H
#define POINTER_LOOP_CLOSURE_CHECKER_H

#include <shared_mutex>
#include <unordered_set>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class PointerLoopClosureChecker {
private:
    class ClosureChecker {
    public:
        int32_t HandleDown(int32_t flag);
        int32_t HandleUpOrCancel(int32_t flag);
        int32_t HandleMove(int32_t flag);

    private:
        int32_t CheckLoopClosure(int32_t flag);
        int32_t UpdatePendingDownFlags(int32_t flag);
        int32_t RemovePendingDownFlags(int32_t flag);

        // pending down flags, buttonId of mouse event, pointerId of touch event
        std::unordered_set<int32_t> pendingFlags_;
        std::shared_mutex rwMutex_;
    };

    int32_t HandleMouseEvent(std::shared_ptr<PointerEvent> event);
    int32_t HandleTouchEvent(std::shared_ptr<PointerEvent> event);

public:
    int32_t CheckAndUpdateEventLoopClosure(std::shared_ptr<PointerEvent> event);

private:
    ClosureChecker closureChecker_;
    std::shared_mutex rwMutex_;
};
} // namespace MMI
} // namespace OHOS
#endif // POINTER_LOOP_CLOSURE_CHECKER_H