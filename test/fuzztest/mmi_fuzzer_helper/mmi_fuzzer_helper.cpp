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

#include "account_manager.h"
#include "ffrt_inner.h"
#include <cstdlib>

namespace OHOS {
namespace MMI {
static void CleanupAccountManager()
{
    auto accountMgr = ACCOUNT_MGR;
    if (accountMgr != nullptr) {
        accountMgr->AccountManagerUnregister();
    }
}

__attribute__((constructor))
static void RegisterCleanup()
{
    std::make_shared<ffrt::queue>("MMI_Fuzz")->submit([]{});
    std::atexit(CleanupAccountManager);
}

} // namespace MMI
} // namespace OHOS
