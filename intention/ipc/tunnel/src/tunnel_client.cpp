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

#include "tunnel_client.h"

#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "iremote_broker.h"
#include "iremote_object.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "TunnelClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

TunnelClient::~TunnelClient()
{
    if (devicestatusProxy_ != nullptr) {
        auto remoteObject = devicestatusProxy_->AsObject();
        if (remoteObject != nullptr) {
            remoteObject->RemoveDeathRecipient(deathRecipient_);
        }
    }
}

int32_t TunnelClient::Enable(Intention intention, ParamBase &data, ParamBase &reply)
{
    CALL_DEBUG_ENTER;
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(IIntention::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken fail");
        return RET_ERR;
    }
    if (!data.Marshalling(dataParcel)) {
        FI_HILOGE("ParamBase::Marshalling fail");
        return RET_ERR;
    }
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    MessageParcel replyParcel;
    int32_t ret = devicestatusProxy_->Enable(intention, dataParcel, replyParcel);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::Enable fail");
        return RET_ERR;
    }
    if (!reply.Unmarshalling(replyParcel)) {
        FI_HILOGE("ParamBase::Unmarshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TunnelClient::Disable(Intention intention, ParamBase &data, ParamBase &reply)
{
    CALL_DEBUG_ENTER;
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(IIntention::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken fail");
        return RET_ERR;
    }
    if (!data.Marshalling(dataParcel)) {
        FI_HILOGE("ParamBase::Marshalling fail");
        return RET_ERR;
    }
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    MessageParcel replyParcel;
    int32_t ret = devicestatusProxy_->Disable(intention, dataParcel, replyParcel);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::Disable fail");
        return RET_ERR;
    }
    if (!reply.Unmarshalling(replyParcel)) {
        FI_HILOGE("ParamBase::Unmarshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TunnelClient::Start(Intention intention, ParamBase &data, ParamBase &reply)
{
    CALL_DEBUG_ENTER;
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(IIntention::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken fail");
        return RET_ERR;
    }
    if (!data.Marshalling(dataParcel)) {
        FI_HILOGE("ParamBase::Marshalling fail");
        return RET_ERR;
    }
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    MessageParcel replyParcel;
    int32_t ret = devicestatusProxy_->Start(intention, dataParcel, replyParcel);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::Start fail");
        return ret;
    }
    if (!reply.Unmarshalling(replyParcel)) {
        FI_HILOGE("ParamBase::Unmarshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TunnelClient::Stop(Intention intention, ParamBase &data, ParamBase &reply)
{
    CALL_DEBUG_ENTER;
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(IIntention::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken fail");
        return RET_ERR;
    }
    if (!data.Marshalling(dataParcel)) {
        FI_HILOGE("ParamBase::Marshalling fail");
        return RET_ERR;
    }
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    MessageParcel replyParcel;
    int32_t ret = devicestatusProxy_->Stop(intention, dataParcel, replyParcel);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::Stop fail");
        return RET_ERR;
    }
    if (!reply.Unmarshalling(replyParcel)) {
        FI_HILOGE("ParamBase::Unmarshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TunnelClient::AddWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
{
    CALL_DEBUG_ENTER;
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(IIntention::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken fail");
        return RET_ERR;
    }
    if (!data.Marshalling(dataParcel)) {
        FI_HILOGE("ParamBase::Marshalling fail");
        return RET_ERR;
    }
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    MessageParcel replyParcel;
    int32_t ret = devicestatusProxy_->AddWatch(intention, id, dataParcel, replyParcel);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::AddWatch fail");
        return RET_ERR;
    }
    if (!reply.Unmarshalling(replyParcel)) {
        FI_HILOGE("ParamBase::Unmarshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TunnelClient::RemoveWatch(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
{
    CALL_DEBUG_ENTER;
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(IIntention::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken fail");
        return RET_ERR;
    }
    if (!data.Marshalling(dataParcel)) {
        FI_HILOGE("ParamBase::Marshalling fail");
        return RET_ERR;
    }
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    MessageParcel replyParcel;
    int32_t ret = devicestatusProxy_->RemoveWatch(intention, id, dataParcel, replyParcel);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::RemoveWatch fail");
        return RET_ERR;
    }
    if (!reply.Unmarshalling(replyParcel)) {
        FI_HILOGE("ParamBase::Unmarshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TunnelClient::SetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
{
    CALL_DEBUG_ENTER;
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(IIntention::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken fail");
        return RET_ERR;
    }
    if (!data.Marshalling(dataParcel)) {
        FI_HILOGE("ParamBase::Marshalling fail");
        return RET_ERR;
    }
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    MessageParcel replyParcel;
    int32_t ret = devicestatusProxy_->SetParam(intention, id, dataParcel, replyParcel);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::SetParam fail");
        return RET_ERR;
    }
    if (!reply.Unmarshalling(replyParcel)) {
        FI_HILOGE("ParamBase::Unmarshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TunnelClient::GetParam(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
{
    CALL_DEBUG_ENTER;
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(IIntention::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken fail");
        return RET_ERR;
    }
    if (!data.Marshalling(dataParcel)) {
        FI_HILOGE("ParamBase::Marshalling fail");
        return RET_ERR;
    }
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    MessageParcel replyParcel;
    int32_t ret = devicestatusProxy_->GetParam(intention, id, dataParcel, replyParcel);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::GetParam fail");
        return RET_ERR;
    }
    if (!reply.Unmarshalling(replyParcel)) {
        FI_HILOGE("ParamBase::Unmarshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t TunnelClient::Control(Intention intention, uint32_t id, ParamBase &data, ParamBase &reply)
{
    CALL_DEBUG_ENTER;
    MessageParcel dataParcel;
    if (!dataParcel.WriteInterfaceToken(IIntention::GetDescriptor())) {
        FI_HILOGE("WriteInterfaceToken fail");
        return RET_ERR;
    }
    if (!data.Marshalling(dataParcel)) {
        FI_HILOGE("ParamBase::Marshalling fail");
        return RET_ERR;
    }
    if (Connect() != RET_OK) {
        FI_HILOGE("Can not connect to IntentionService");
        return RET_ERR;
    }
    MessageParcel replyParcel;
    int32_t ret = devicestatusProxy_->Control(intention, id, dataParcel, replyParcel);
    if (ret != RET_OK) {
        FI_HILOGE("proxy::Control fail");
        return RET_ERR;
    }
    if (!reply.Unmarshalling(replyParcel)) {
        FI_HILOGE("ParamBase::Unmarshalling fail");
        return RET_ERR;
    }
    return RET_OK;
}

ErrCode TunnelClient::Connect()
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    if (devicestatusProxy_ != nullptr) {
        return RET_OK;
    }

    sptr<ISystemAbilityManager> sa = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHKPR(sa, E_DEVICESTATUS_GET_SYSTEM_ABILITY_MANAGER_FAILED);

    sptr<IRemoteObject> remoteObject = sa->CheckSystemAbility(MSDP_DEVICESTATUS_SERVICE_ID);
    CHKPR(remoteObject, E_DEVICESTATUS_GET_SERVICE_FAILED);

    deathRecipient_ = sptr<DeathRecipient>::MakeSptr(shared_from_this());
    CHKPR(deathRecipient_, ERR_NO_MEMORY);

    if (remoteObject->IsProxyObject()) {
        if (!remoteObject->AddDeathRecipient(deathRecipient_)) {
            FI_HILOGE("Add death recipient to DeviceStatus service failed");
            return E_DEVICESTATUS_ADD_DEATH_RECIPIENT_FAILED;
        }
    }

    devicestatusProxy_ = iface_cast<IIntention>(remoteObject);
    FI_HILOGD("Connecting IntentionService success");
    return RET_OK;
}

void TunnelClient::ResetProxy(const wptr<IRemoteObject> &remote)
{
    CALL_DEBUG_ENTER;
    std::lock_guard lock(mutex_);
    CHKPV(devicestatusProxy_);
    auto serviceRemote = devicestatusProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        devicestatusProxy_ = nullptr;
    }
}

TunnelClient::DeathRecipient::DeathRecipient(std::shared_ptr<TunnelClient> parent)
    : parent_(parent)
{}

void TunnelClient::DeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<TunnelClient> parent = parent_.lock();
    CHKPV(parent);
    CHKPV(remote);
    parent->ResetProxy(remote);
    FI_HILOGD("Recv death notice");
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
