/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "authorization_dialog.h"

#include <atomic>

#include "ability_manager_client.h"
#include "message_parcel.h"

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AuthorizationDialog"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INVALID_USERID { -1 };
constexpr int32_t MESSAGE_PARCEL_KEY_SIZE { 3 };
std::atomic_bool g_isDialogShow = false;
sptr<IRemoteObject> g_remoteObject = nullptr;
}

std::string AuthorizationDialog::bundleName_ = "com.ohos.powerdialog";
std::string AuthorizationDialog::abilityName_ = "PowerUiExtensionAbility";
std::string AuthorizationDialog::uiExtensionType_ = "sysDialog/power";

AuthorizationDialog::AuthorizationDialog() : dialogConnectionCallback_(new DialogAbilityConnection()) {}

AuthorizationDialog::~AuthorizationDialog()
{
    dialogConnectionCallback_ = nullptr;
}

bool AuthorizationDialog::ConnectSystemUi()
{
    CHKPR(dialogConnectionCallback_, false);
    if (g_isDialogShow) {
        AppExecFwk::ElementName element;
        dialogConnectionCallback_->OnAbilityConnectDone(element, g_remoteObject, INVALID_USERID);
        MMI_HILOGW("Power dialog has been show");
        return true;
    }
    auto abilityMgr = AAFwk::AbilityManagerClient::GetInstance();
    CHKPF(abilityMgr);

    AAFwk::Want want;
    want.SetElementName("com.ohos.systemui", "com.ohos.systemui.dialog");
    ErrCode result = abilityMgr->ConnectAbility(want, dialogConnectionCallback_, INVALID_USERID);
    if (result != ERR_OK) {
        MMI_HILOGW("ConnectAbility systemui dialog failed, result:%{public}d", result);
        return false;
    }
    MMI_HILOGI("ConnectAbility systemui dialog success");
    return true;
}

void AuthorizationDialog::DialogAbilityConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode)
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    CHKPV(remoteObject);
    if (g_remoteObject == nullptr) {
        g_remoteObject = remoteObject;
    }
    ffrt::submit([remoteObject] {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInt32(MESSAGE_PARCEL_KEY_SIZE);
        data.WriteString16(u"bundleName");
        data.WriteString16(Str8ToStr16(AuthorizationDialog::GetBundleName()));
        data.WriteString16(u"abilityName");
        data.WriteString16(Str8ToStr16(AuthorizationDialog::GetAbilityName()));
        data.WriteString16(u"parameters");
        std::string midStr = "\"";
        std::string paramStr = "{\"ability.want.params.uiExtensionType\":"+ midStr +
            AuthorizationDialog::GetUiExtensionType() + midStr + ",\"sysDialogZOrder\":2,\"isInputDlg\":true}";
        data.WriteString16(Str8ToStr16(paramStr));
        MMI_HILOGI("Show power dialog is begin");
        const uint32_t cmdCode = 1;
        int32_t ret = remoteObject->SendRequest(cmdCode, data, reply, option);
        if (ret != ERR_OK) {
            MMI_HILOGW("Show power dialog is failed:%{public}d", ret);
            return;
        }
        g_isDialogShow = true;
        MMI_HILOGI("Show power dialog is success");
    });
}

void AuthorizationDialog::DialogAbilityConnection::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName& element, int resultCode)
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    g_isDialogShow = false;
    g_remoteObject = nullptr;
}
} // namespace MMI
} // namespace OHOS