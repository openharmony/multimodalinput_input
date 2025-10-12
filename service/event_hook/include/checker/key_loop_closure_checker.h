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

#ifndef KEY_LOOP_CLOSURE_CHECKER_H
#define KEY_LOOP_CLOSURE_CHECKER_H

#include <shared_mutex>
#include <unordered_set>

#include "key_event.h"

namespace OHOS {
namespace MMI {
class KeyLoopClosureChecker {
public:
    int32_t CheckAndUpdateEventLoopClosure(std::shared_ptr<KeyEvent> keyEvent);

private:
    int32_t HandleEventLoopClosureKeyDown(int32_t keyCode);
    int32_t HandleEventLoopClosureKeyUpOrCancel(int32_t keyCode);
    int32_t CheckLoopClosure(int32_t keyCode);
    int32_t UpdatePendingDownKeys(int32_t keyCode);
    int32_t RemovePendingDownKeys(int32_t keyCode);
private:
    std::unordered_set<int32_t> pendingDownKeys_; // pending down keyCode
    std::shared_mutex rwMutex_;
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_LOOP_CLOSURE_CHECKER_H