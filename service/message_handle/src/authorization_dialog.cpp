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

#include "ability_manager_client.h"
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
#include "dfx_hisysevent.h"
#endif // OHOS_BUILD_ENABLE_DFX_RADAR

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
}

std::string AuthorizationDialog::bundleName_ = "com.ohos.powerdialog";
std::string AuthorizationDialog::abilityName_ = "PowerUiExtensionAbility";
std::string AuthorizationDialog::uiExtensionType_ = "sysDialog/power";

AuthorizationDialog::AuthorizationDialog() : dialogConnectionCallback_(new DialogAbilityConnection()) {}

AuthorizationDialog::~AuthorizationDialog()
{
    CALL_DEBUG_ENTER;
    CloseDialog();
    dialogConnectionCallback_ = nullptr;
}

bool AuthorizationDialog::ConnectSystemUi()
{
    CALL_DEBUG_ENTER;
    CHKPR(dialogConnectionCallback_, false);
    if (dialogConnectionCallback_->DialogIsOpen()) {
        MMI_HILOGW("Power dialog has been show");
        return true;
    }

    if (dialogConnectionCallback_->IsConnected()) {
        MMI_HILOGW("Dialog reopens");
        dialogConnectionCallback_->OpenDialog();
        return true;
    }
    MMI_HILOGI("ConnectAbility systemui beigin");
    auto abilityMgr = AAFwk::AbilityManagerClient::GetInstance();
    CHKPF(abilityMgr);

    AAFwk::Want want;
    want.SetElementName("com.ohos.sceneboard", "com.ohos.sceneboard.systemdialog");
    auto begin = std::chrono::high_resolution_clock::now();
    ErrCode result = abilityMgr->ConnectAbility(want, dialogConnectionCallback_, INVALID_USERID);
    auto durationMS = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - begin).count();
#ifdef OHOS_BUILD_ENABLE_DFX_RADAR
    DfxHisysevent::ReportApiCallTimes(ApiDurationStatistics::Api::ABILITY_MGR_CONNECT_ABILITY, durationMS);
#endif // OHOS_BUILD_ENABLE_DFX_RADAR
    if (result != ERR_OK) {
        MMI_HILOGW("ConnectAbility systemui dialog failed, result:%{public}d", result);
        return false;
    }
    MMI_HILOGI("ConnectAbility systemui dialog success");
    return true;
}

void AuthorizationDialog::CloseDialog()
{
    CALL_DEBUG_ENTER;
    dialogConnectionCallback_->CloseDialog();
}

void AuthorizationDialog::DialogAbilityConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode)
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    CHKPV(remoteObject);
    if (remoteObject_ == nullptr) {
        remoteObject_ = remoteObject;
    }
    ffrt::submit([&] {
        this->OpenDialog();
    });
}

void AuthorizationDialog::DialogAbilityConnection::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName& element, int resultCode)
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    remoteObject_ = nullptr;
    // disconnted window must be shutdown
    isDialogShow_ = false;
}

void AuthorizationDialog::DialogAbilityConnection::CloseDialog()
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    CHKPV(remoteObject_);
    if (!isDialogShow_) {
        MMI_HILOGI("Has closed!");
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    const uint32_t cmdCode = 3;
    int32_t ret = remoteObject_->SendRequest(cmdCode, data, reply, option);
    int32_t replyCode = -1;
    bool success = false;
    if (ret == ERR_OK) {
        success = reply.ReadInt32(replyCode);
    }
    isDialogShow_ = false;
    MMI_HILOGI("CloseDialog: ret=%d, %d, %d", ret, success, replyCode);
}

void AuthorizationDialog::DialogAbilityConnection::OpenDialog()
{
    CALL_DEBUG_ENTER;
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
    std::lock_guard lock(mutex_);
    CHKPV(remoteObject_);
    int32_t ret = remoteObject_->SendRequest(cmdCode, data, reply, option);
    if (ret != ERR_OK) {
        MMI_HILOGW("Show power dialog is failed:%{public}d", ret);
        return;
    }
    isDialogShow_ = true;
    MMI_HILOGI("Show power dialog is success");
}

bool AuthorizationDialog::DialogAbilityConnection::DialogIsOpen()
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    return isDialogShow_;
}

bool AuthorizationDialog::DialogAbilityConnection::IsConnected()
{
    std::lock_guard lock(mutex_);
    if (remoteObject_ != nullptr) {
        return true;
    }
    return false;
}
} // namespace MMI
} // namespace OHOS