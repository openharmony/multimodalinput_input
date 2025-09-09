/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "accountsetting_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "want.h"

#include "securec.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AccountSettingFuzzTest"

namespace OHOS {
namespace MMI {
bool AccountSettingFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::AAFwk::Want want;
    std::string str = provider.ConsumeRandomLengthString();
    want.SetAction(str);
    EventFwk::CommonEventData eventdata;
    eventdata.SetWant(want);
    ACCOUNT_MGR->SubscribeCommonEvent();
    if (ACCOUNT_MGR->subscriber_) {
        ACCOUNT_MGR->subscriber_->OnReceiveEvent(eventdata);
    }

    int32_t accountId = provider.ConsumeIntegral<int32_t>();
    AccountManager::AccountSetting accountSetting2(accountId);
    int32_t accShortcutTimeout = provider.ConsumeIntegral<int32_t>();
    bool accShortcutEnabled = provider.ConsumeBool();
    bool accShortcutEnabledOnScreenLocked = provider.ConsumeBool();
    accountSetting2.accShortcutTimeout_ = accShortcutTimeout;
    accountSetting2.accShortcutEnabled_ = accShortcutEnabled;
    accountSetting2.accShortcutEnabledOnScreenLocked_ = accShortcutEnabledOnScreenLocked;

    AccountManager::AccountSetting accountSetting = accountSetting2;

    int32_t key = provider.ConsumeIntegral<int32_t>();
    int32_t currentAccountId = provider.ConsumeIntegral<int32_t>();
    auto accountSettingTemp = std::make_unique<AccountManager::AccountSetting>(currentAccountId);
    ACCOUNT_MGR->accounts_.insert(std::make_pair(key, std::move(accountSettingTemp)));

    accountId = provider.ConsumeIntegral<int32_t>();
    str = provider.ConsumeRandomLengthString();
    accountSetting.AccShortcutTimeout(accountId, str);

    accountId = provider.ConsumeIntegral<int32_t>();
    str = provider.ConsumeRandomLengthString();
    accountSetting.AccShortcutEnabled(accountId, str);

    accountId = provider.ConsumeIntegral<int32_t>();
    str = provider.ConsumeRandomLengthString();
    accountSetting.AccShortcutEnabledOnScreenLocked(accountId, str);
    return true;
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

    OHOS::MMI::AccountSettingFuzzTest(data, size);
    return 0;
}
