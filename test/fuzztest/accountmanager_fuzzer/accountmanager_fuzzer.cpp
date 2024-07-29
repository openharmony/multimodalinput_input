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
#include "accountmanager_fuzzer.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AccountManagerFuzzTest"

namespace OHOS {
namespace MMI {


int32_t accountId = 1;
std::string key = "hello";
// int32_t accountId = data.GetCode();
// accountId = 2;
// accountManager.currentAccountId_ = -1;
bool currentSwitchStatus = true;

bool AccountManagerFuzzTest(const uint8_t *data, size_t size)
{
    const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.multimodalinput.IConnectManager" };
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    // auto accountManager = ACCOUNT_MGR;


    // accountManager->AccShortcutEnabled(accountId, key);
    // accountManager->AccShortcutEnabledOnScreenLocked(accountId, key);
    //accountManager->InitializeSetting();
    // accountManager->OnAccShortcutTimeoutChanged(key);
    // accountManager->OnAccShortcutEnabled(key);
    // accountManager->OnAccShortcutEnabledOnScreenLocked(key);
    // accountManager->ReadSwitchStatus(key, currentSwitchStatus);
    // accountManager->ReadLongPressTime();
    // accountManager->AccountManager();
    
    ACCOUNT_MGR->GetCurrentAccountSetting();
    ACCOUNT_MGR->SubscribeCommonEvent();
    ACCOUNT_MGR->UnsubscribeCommonEvent();
    ACCOUNT_MGR->SetupMainAccount();
    
    
    // accountManager->OnSwitchUser(fuzzdata);
    // accountManager->OnCommonEvent(fuzzdata);
    // accountManager->OnAddUser(fuzzdata);
    // accountManager->OnRemoveUser(fuzzdata);
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

    OHOS::MMI::AccountManagerFuzzTest(data, size);
    return 0;
}
