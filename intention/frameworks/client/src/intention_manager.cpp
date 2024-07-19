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

#include "intention_manager.h"

#include "display_manager.h"

#include "devicestatus_define.h"
#include "drag_data.h"

#undef LOG_TAG
#define LOG_TAG "IntentionManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr int32_t INDEX_MAIN { 0 };
constexpr int32_t INDEX_FULL { 1 };
constexpr size_t POLICY_VEC_SIZE { 2 };
const std::string SCREEN_ROTATION { "1" };
} // namespace

IntentionManager::IntentionManager()
{
    tunnel_ = std::make_shared<TunnelClient>();
}

IntentionManager::~IntentionManager()
{
    client_.reset();
}

void IntentionManager::InitClient()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    if (client_ != nullptr) {
        return;
    }
    client_ = std::make_unique<SocketClient>(tunnel_);
    InitMsgHandler();
    client_->Start();
    GetRotatePolicy(isScreenRotation_, foldRotatePolicys_);
}

void IntentionManager::InitMsgHandler()
{
    CALL_DEBUG_ENTER;
    std::map<MessageId, std::function<int32_t(const StreamClient&, NetPacket&)>> funs {
#ifdef OHOS_BUILD_ENABLE_COORDINATION
        {MessageId::COORDINATION_ADD_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnCoordinationListener(client, pkt);
        }},
        {MessageId::COORDINATION_MESSAGE, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnCoordinationMessage(client, pkt);
        }},
        {MessageId::COORDINATION_GET_STATE, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnCoordinationState(client, pkt);
        }},
        {MessageId::HOT_AREA_ADD_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnHotAreaListener(client, pkt);
        }},
        {MessageId::MOUSE_LOCATION_ADD_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->cooperate_.OnMouseLocationListener(client, pkt);
        }},
#endif // OHOS_BUILD_ENABLE_COORDINATION

        {MessageId::DRAG_NOTIFY_RESULT, [this](const StreamClient &client, NetPacket &pkt) {
            return this->drag_.OnNotifyResult(client, pkt);
        }},
        {MessageId::DRAG_STATE_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->drag_.OnStateChangedMessage(client, pkt);
        }},
        {MessageId::DRAG_NOTIFY_HIDE_ICON, [this](const StreamClient &client, NetPacket &pkt) {
            return this->drag_.OnNotifyHideIcon(client, pkt);
        }},
        {MessageId::DRAG_STYLE_LISTENER, [this](const StreamClient &client, NetPacket &pkt) {
            return this->drag_.OnDragStyleChangedMessage(client, pkt);
        }},
        {MessageId::ADD_SELECTED_PIXELMAP_RESULT, [this](const StreamClient &client, NetPacket &pkt) {
            return this->drag_.OnAddSelectedPixelMapResult(client, pkt);
        }}
    };
    CHKPV(client_);
    for (auto &[id, cb] : funs) {
        if (!client_->RegisterEvent(id, cb)) {
            FI_HILOGI("RegistER event handler msg:%{publid}d already exists", id);
        }
    }
}

int32_t IntentionManager::SubscribeCallback(Type type, ActivityEvent event, ReportLatencyNs latency,
    sptr<IRemoteDevStaCallback> callback)
{
    return stationary_.SubscribeCallback(*tunnel_, type, event, latency, callback);
}

int32_t IntentionManager::UnsubscribeCallback(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback)
{
    return stationary_.UnsubscribeCallback(*tunnel_, type, event, callback);
}

Data IntentionManager::GetDeviceStatusData(const Type type)
{
    return stationary_.GetDeviceStatusData(*tunnel_, type);
}

int32_t IntentionManager::RegisterCoordinationListener(
    std::shared_ptr<ICoordinationListener> listener, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.RegisterListener(*tunnel_, listener, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(listener);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UnregisterCoordinationListener(
    std::shared_ptr<ICoordinationListener> listener, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return cooperate_.UnregisterListener(*tunnel_, listener, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(listener);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::PrepareCoordination(CooperateMsgInfoCallback callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.Enable(*tunnel_, callback, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(callback);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UnprepareCoordination(CooperateMsgInfoCallback callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.Disable(*tunnel_, callback, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(callback);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::ActivateCoordination(const std::string &remoteNetworkId, int32_t startDeviceId,
    CooperateMsgInfoCallback callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.Start(*tunnel_, remoteNetworkId, startDeviceId, callback, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(remoteNetworkId);
    (void)(startDeviceId);
    (void)(callback);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::DeactivateCoordination(bool isUnchained,
    CooperateMsgInfoCallback callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.Stop(*tunnel_, isUnchained, callback, isCompatible);
#else
    FI_HILOGW("Coordination does not support");
    (void)(callback);
    (void)(isCompatible);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::GetCoordinationState(
    const std::string &networkId, std::function<void(bool)> callback, bool isCompatible)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.GetCooperateState(*tunnel_, networkId, callback, isCompatible);
#else
    (void)(networkId);
    (void)(callback);
    (void)(isCompatible);
    FI_HILOGW("Coordination does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::GetCoordinationState(const std::string &udId, bool &state)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.GetCooperateState(*tunnel_, udId, state);
#else
    (void)(udId);
    (void)(state);
    FI_HILOGW("Coordination does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::RegisterEventListener(const std::string &networkId, std::shared_ptr<IEventListener> listener)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.RegisterEventListener(*tunnel_, networkId, listener);
#else
    (void)(networkId);
    (void)(listener);
    FI_HILOGW("Coordination does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UnregisterEventListener(const std::string &networkId,
    std::shared_ptr<IEventListener> listener)
{
    CALL_INFO_TRACE;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.UnregisterEventListener(*tunnel_, networkId, listener);
#else
    (void)(networkId);
    (void)(listener);
    FI_HILOGW("Coordination does not support");
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UpdateDragStyle(DragCursorStyle style)
{
    CALL_DEBUG_ENTER;
    return drag_.UpdateDragStyle(*tunnel_, style);
}

int32_t IntentionManager::StartDrag(const DragData &dragData, std::shared_ptr<IStartDragListener> listener)
{
    CALL_DEBUG_ENTER;
    InitClient();
    return drag_.StartDrag(*tunnel_, dragData, listener);
}

int32_t IntentionManager::StopDrag(const DragDropResult &dropResult)
{
    CALL_DEBUG_ENTER;
    return drag_.StopDrag(*tunnel_, dropResult);
}

int32_t IntentionManager::GetDragTargetPid()
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragTargetPid(*tunnel_);
}

int32_t IntentionManager::GetUdKey(std::string &udKey)
{
    CALL_DEBUG_ENTER;
    return drag_.GetUdKey(*tunnel_, udKey);
}

int32_t IntentionManager::AddDraglistener(DragListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    InitClient();
    return drag_.AddDraglistener(*tunnel_, listener);
}

int32_t IntentionManager::RemoveDraglistener(DragListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    return drag_.RemoveDraglistener(*tunnel_, listener);
}

int32_t IntentionManager::AddSubscriptListener(SubscriptListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    InitClient();
    return drag_.AddSubscriptListener(*tunnel_, listener);
}

int32_t IntentionManager::RemoveSubscriptListener(SubscriptListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    return drag_.RemoveSubscriptListener(*tunnel_, listener);
}

int32_t IntentionManager::SetDragWindowVisible(bool visible, bool isForce)
{
    CALL_DEBUG_ENTER;
    return drag_.SetDragWindowVisible(*tunnel_, visible, isForce);
}

int32_t IntentionManager::GetShadowOffset(ShadowOffset &shadowOffset)
{
    CALL_DEBUG_ENTER;
    return drag_.GetShadowOffset(*tunnel_, shadowOffset);
}

int32_t IntentionManager::UpdateShadowPic(const ShadowInfo &shadowInfo)
{
    CALL_DEBUG_ENTER;
    return drag_.UpdateShadowPic(*tunnel_, shadowInfo);
}

int32_t IntentionManager::GetDragData(DragData &dragData)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragData(*tunnel_, dragData);
}

int32_t IntentionManager::GetDragState(DragState &dragState)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragState(*tunnel_, dragState);
}

int32_t IntentionManager::GetDragAction(DragAction &dragAction)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragAction(*tunnel_, dragAction);
}

int32_t IntentionManager::GetExtraInfo(std::string &extraInfo)
{
    CALL_DEBUG_ENTER;
    return drag_.GetExtraInfo(*tunnel_, extraInfo);
}

int32_t IntentionManager::AddHotAreaListener(std::shared_ptr<IHotAreaListener> listener)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    InitClient();
    return cooperate_.AddHotAreaListener(*tunnel_, listener);
#else
    FI_HILOGW("Coordination does not support");
    (void)(listener);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::RemoveHotAreaListener(std::shared_ptr<IHotAreaListener> listener)
{
    CALL_DEBUG_ENTER;
#ifdef OHOS_BUILD_ENABLE_COORDINATION
    return cooperate_.RemoveHotAreaListener(*tunnel_, listener);
#else
    FI_HILOGW("Coordination does not support");
    (void)(listener);
    return ERROR_UNSUPPORT;
#endif // OHOS_BUILD_ENABLE_COORDINATION
}

int32_t IntentionManager::UpdatePreviewStyle(const PreviewStyle &previewStyle)
{
    CALL_DEBUG_ENTER;
    return drag_.UpdatePreviewStyle(*tunnel_, previewStyle);
}

int32_t IntentionManager::UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle,
    const PreviewAnimation &animation)
{
    CALL_DEBUG_ENTER;
    return drag_.UpdatePreviewStyleWithAnimation(*tunnel_, previewStyle, animation);
}

int32_t IntentionManager::RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    CALL_DEBUG_ENTER;
    if (isScreenRotation_) {
        FI_HILOGW("Screen rotation, not need rotate drag window");
        return RET_OK;
    }
    if (Rosen::DisplayManager::GetInstance().IsFoldable()) {
        if ((foldRotatePolicys_.empty()) || (foldRotatePolicys_.size() < POLICY_VEC_SIZE)) {
            FI_HILOGE("foldRotatePolicys_ is invalid");
            return drag_.RotateDragWindowSync(*tunnel_, rsTransaction);
        }
        if (Rosen::DisplayManager::GetInstance().GetFoldDisplayMode() == Rosen::FoldDisplayMode::FULL) {
            if (foldRotatePolicys_[INDEX_FULL] == SCREEN_ROTATION) {
                FI_HILOGD("Full display rotation, not need rotate drag window");
                return RET_OK;
            }
        } else if (Rosen::DisplayManager::GetInstance().GetFoldDisplayMode() == Rosen::FoldDisplayMode::MAIN) {
            if (foldRotatePolicys_[INDEX_MAIN] == SCREEN_ROTATION) {
                FI_HILOGD("Main display rotation, not need rotate drag window");
                return RET_OK;
            }
        }
    }
    return drag_.RotateDragWindowSync(*tunnel_, rsTransaction);
}

int32_t IntentionManager::SetDragWindowScreenId(uint64_t displayId, uint64_t screenId)
{
    CALL_DEBUG_ENTER;
    return drag_.SetDragWindowScreenId(*tunnel_, displayId, screenId);
}

int32_t IntentionManager::GetDragSummary(std::map<std::string, int64_t> &summarys)
{
    CALL_DEBUG_ENTER;
    return drag_.GetDragSummary(*tunnel_, summarys);
}

int32_t IntentionManager::EnterTextEditorArea(bool enable)
{
    CALL_DEBUG_ENTER;
    return drag_.EnterTextEditorArea(*tunnel_, enable);
}

int32_t IntentionManager::AddPrivilege()
{
    CALL_DEBUG_ENTER;
    return drag_.AddPrivilege(*tunnel_);
}

int32_t IntentionManager::EraseMouseIcon()
{
    CALL_DEBUG_ENTER;
    return drag_.EraseMouseIcon(*tunnel_);
}

int32_t IntentionManager::AddSelectedPixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap,
    std::function<void(bool)> callback)
{
    CALL_DEBUG_ENTER;
    return drag_.AddSelectedPixelMap(*tunnel_, pixelMap, callback);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
