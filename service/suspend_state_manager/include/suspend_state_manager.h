/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MMI_SUSPEND_STATE_MANAGER_H
#define MMI_SUSPEND_STATE_MANAGER_H

#include <memory>
#include <mutex>
#include <unordered_set>
#include <vector>
#include "define_multimodal.h"
#include "nocopyable.h"
#include "suspend_state_observer_base_stub.h"

namespace OHOS {
namespace MMI {

class SuspendStateObserver : public ResourceSchedule::SuspendStateObserverBaseStub {
public:
    ~SuspendStateObserver();
    static sptr<SuspendStateObserver> GetInstance();
    virtual ErrCode OnActive(const std::vector<int32_t> &pidList, int32_t uid) override;
    virtual ErrCode OnDoze(const std::vector<int32_t> &pidList, int32_t uid) override
    {
        return RET_OK;
    }
    virtual ErrCode OnFrozen(const std::vector<int32_t> &pidList, int32_t uid) override;
    bool IsFrozenPid(int32_t pid);
    std::unordered_set<int32_t> GetFrozenPidList();

private:
    std::mutex mutex_;
    std::unordered_set<int32_t> frozenPidList_;
};

class SuspendStateManager {
public:
    SuspendStateManager();
    ~SuspendStateManager();
    DISALLOW_COPY_AND_MOVE(SuspendStateManager);

    static SuspendStateManager &GetInstance();

    int32_t RegisterSuspendStateChanged();
    int32_t UnRegisterSuspendStateChanged();
    bool IsFrozen(int32_t pid);
    void SetRssSaReady();
    void SetSuspendSaReady();
    void Dump(int32_t fd);

private:
    sptr<SuspendStateObserver> suspendStateObserver_;
    std::atomic_bool isRssSaReady_ { false };
    std::atomic_bool isSuspendManagerSaReady_ { false };
    std::atomic_bool hasRegisteredObserver_ { false };
};

} // namespace MMI
} // namespace OHOS
#endif // MMI_SUSPEND_STATE_MANAGER_H
