/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "safe_keeper.h"
#include <inttypes.h>
#include "log.h"
#include "util.h"

namespace OHOS::MMI {
    namespace {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "SafeKeeper" };
    }
}

OHOS::MMI::SafeKeeper::SafeKeeper()
{
}

OHOS::MMI::SafeKeeper::~SafeKeeper()
{
}

void OHOS::MMI::SafeKeeper::Init(SafeCallbackFun fun)
{
    cbFun_ = fun;
}

bool OHOS::MMI::SafeKeeper::RegisterEvent(uint64_t tid, const std::string& remark)
{
    CHKF(!IsExist(tid), PARAM_INPUT_INVALID);
    CHKF(!remark.empty(), PARAM_INPUT_INVALID);
    std::lock_guard<std::mutex> lock(mtx_);
    const SafeEvent event = {tid, GetCurMillisTime(), remark};
    dList_.push_back(event);
    MMI_LOGI("SafeKeeper register tid:[%{public}" PRId64 "] remark:[%{public}s]", tid, remark.c_str());
    return true;
}

void OHOS::MMI::SafeKeeper::ClearAll()
{
    std::lock_guard<std::mutex> lock(mtx_);
    dList_.clear();
    cbFun_ = nullptr;
}

void OHOS::MMI::SafeKeeper::ReportHealthStatus(uint64_t tid)
{
    CHK(tid > 0, PARAM_INPUT_INVALID);
    std::lock_guard<std::mutex> lock(mtx_);
    auto ptr = GetEvent(tid);
    if (!ptr) {
        MMI_LOGE("SafeKeeper report ptr = nullptr tid:[%{public}" PRId64 "] errCode:%{public}d", tid, NULL_POINTER);
        return;
    }
    ptr->lastTime = GetCurMillisTime();
}

void OHOS::MMI::SafeKeeper::ProcessEvents()
{
    if (dList_.empty()) {
        return;
    }
    int32_t pastTime = 0;
    auto curTime = GetCurMillisTime();

    std::lock_guard<std::mutex> lock(mtx_);
    for (auto& it : dList_) {
        pastTime = static_cast<int32_t>(curTime - it.lastTime);
        if (pastTime > MAX_THREAD_DEATH_TIME) {
            cbFun_(pastTime, it.tid, it.remark);
            return;
        }
    }
}
