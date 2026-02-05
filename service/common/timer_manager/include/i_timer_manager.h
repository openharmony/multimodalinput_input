/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef I_TIMER_MANAGER_H
#define I_TIMER_MANAGER_H

#include <cstdint>
#include <functional>
#include <string>

namespace OHOS {
namespace MMI {
class ITimerManager {
public:
    ITimerManager() = default;
    virtual ~ITimerManager() = default;

    virtual int32_t AddTimer(int32_t intervalMs, int32_t repeatCount,
        std::function<void()> callback, const std::string &name = "") = 0;
    virtual int32_t RemoveTimer(int32_t timerId, const std::string &name = "") = 0;
    virtual bool IsExist(int32_t timerId);
    virtual int32_t ResetTimer(int32_t timerId);
};
} // namespace MMI
} // namespace OHOS
#endif // I_TIMER_MANAGER_H
