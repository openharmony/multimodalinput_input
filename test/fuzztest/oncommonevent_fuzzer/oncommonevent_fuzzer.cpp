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
#include "oncommonevent_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "want.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "OnCommonEventFuzzTest"

namespace OHOS {
namespace MMI {
void OnCommonEvent(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int32_t timeId = provider.ConsumeIntegral<int32_t>();
    int32_t currentAccountId = provider.ConsumeIntegral<int32_t>();
    ACCOUNT_MGR->timerId_ = timeId;
    ACCOUNT_MGR->currentAccountId_ = currentAccountId;
    int32_t key = provider.ConsumeIntegral<int32_t>();
    currentAccountId = provider.ConsumeIntegral<int32_t>();
    auto accountSetting = std::make_unique<AccountManager::AccountSetting>(currentAccountId);
    ACCOUNT_MGR->accounts_.insert(std::make_pair(key, std::move(accountSetting)));
    std::string str = provider.ConsumeRandomLengthString();
    auto callback = [](const EventFwk::CommonEventData &) {};
    ACCOUNT_MGR->handlers_.insert(std::make_pair(str, std::move(callback)));
    OHOS::AAFwk::Want want;
    want.SetAction(str);
    EventFwk::CommonEventData eventdata;
    eventdata.SetWant(want);
    currentAccountId = provider.ConsumeIntegral<int32_t>();
    eventdata.SetCode(currentAccountId);
    ACCOUNT_MGR->OnCommonEvent(eventdata);
    ACCOUNT_MGR->OnAddUser(eventdata);
    ACCOUNT_MGR->OnRemoveUser(eventdata);
    ACCOUNT_MGR->OnSwitchUser(eventdata);
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::OnCommonEvent(data, size);
    return 0;
}
