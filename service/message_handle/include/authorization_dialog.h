/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef AUTHORIZATION_DIALOG_H
#define AUTHORIZATION_DIALOG_H

#include "ability_connect_callback_stub.h"
#include "ffrt_inner.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class AuthorizationDialog final {
    DECLARE_SINGLETON(AuthorizationDialog);
public:
    DISALLOW_MOVE(AuthorizationDialog);
    bool ConnectSystemUi();
    static std::string GetBundleName()
    {
        return bundleName_;
    }

    static std::string GetAbilityName()
    {
        return abilityName_;
    }

    static std::string GetUiExtensionType()
    {
        return uiExtensionType_;
    }
    void CloseDialog();
private:
    class DialogAbilityConnection : public OHOS::AAFwk::AbilityConnectionStub {
    public:
        void OnAbilityConnectDone(
            const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode) override;
        void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) override;
        void CloseDialog();
        bool DialogIsOpen();
        void OpenDialog();
        bool IsConnected();

    private:
        std::mutex mutex_;
        std::atomic_bool isDialogShow_ { false };
        sptr<IRemoteObject> remoteObject_ { nullptr };
    };

    sptr<DialogAbilityConnection> dialogConnectionCallback_ { nullptr };
    static std::string bundleName_;
    static std::string abilityName_;
    static std::string uiExtensionType_;
};

#define AUTH_DIALOG ::OHOS::Singleton<AuthorizationDialog>::GetInstance()
} // namespace MMI
} // namespace OHOS

#endif // AUTHORIZATION_DIALOG_H