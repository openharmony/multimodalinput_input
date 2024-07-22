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

#ifndef INTENTION_MANAGER_H
#define INTENTION_MANAGER_H

#include <mutex>

#include "singleton.h"

#include "cooperate_client.h"
#include "drag_client.h"
#include "drag_data.h"
#include "drag_manager_impl.h"
#include "i_event_listener.h"
#include "socket_client.h"
#include "stationary_client.h"
#include "tunnel_client.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IntentionManager {
    DECLARE_SINGLETON(IntentionManager);
    using CooperateMsgInfoCallback = std::function<void(const std::string&, const CoordinationMsgInfo&)>;

public:
    DISALLOW_MOVE(IntentionManager);
    int32_t SubscribeCallback(Type type, ActivityEvent event, ReportLatencyNs latency,
        sptr<IRemoteDevStaCallback> callback);
    int32_t UnsubscribeCallback(Type type, ActivityEvent event, sptr<IRemoteDevStaCallback> callback);
    Data GetDeviceStatusData(const Type type);
    int32_t RegisterCoordinationListener(
        std::shared_ptr<ICoordinationListener> listener, bool isCompatible = false);
    int32_t UnregisterCoordinationListener(
        std::shared_ptr<ICoordinationListener> listener, bool isCompatible = false);
    int32_t PrepareCoordination(CooperateMsgInfoCallback callback, bool isCompatible = false);
    int32_t UnprepareCoordination(CooperateMsgInfoCallback callback, bool isCompatible = false);
    int32_t ActivateCoordination(const std::string &remoteNetworkId, int32_t startDeviceId,
        CooperateMsgInfoCallback callback, bool isCompatible = false);
    int32_t DeactivateCoordination(bool isUnchained, CooperateMsgInfoCallback callback, bool isCompatible = false);
    int32_t GetCoordinationState(const std::string &networkId, std::function<void(bool)> callback,
        bool isCompatible = false);
    int32_t GetCoordinationState(const std::string &udId, bool &state);
    int32_t RegisterEventListener(const std::string &networkId, std::shared_ptr<IEventListener> listener);
    int32_t UnregisterEventListener(const std::string &networkId, std::shared_ptr<IEventListener> listener = nullptr);
    int32_t UpdateDragStyle(DragCursorStyle style);
    int32_t StartDrag(const DragData &dragData, std::shared_ptr<IStartDragListener> listener);
    int32_t StopDrag(const DragDropResult &dropResult);
    int32_t GetDragTargetPid();
    int32_t GetUdKey(std::string &udKey);
    int32_t AddDraglistener(DragListenerPtr listener);
    int32_t RemoveDraglistener(DragListenerPtr listener);
    int32_t AddSubscriptListener(SubscriptListenerPtr listener);
    int32_t RemoveSubscriptListener(SubscriptListenerPtr listener);
    int32_t SetDragWindowVisible(bool visible, bool isForce = false);
    int32_t GetShadowOffset(ShadowOffset &shadowOffset);
    int32_t UpdateShadowPic(const ShadowInfo &shadowInfo);
    int32_t GetDragData(DragData &dragData);
    int32_t GetDragState(DragState &dragState);
    int32_t AddHotAreaListener(std::shared_ptr<IHotAreaListener> listener);
    int32_t RemoveHotAreaListener(std::shared_ptr<IHotAreaListener> listener = nullptr);
    int32_t UpdatePreviewStyle(const PreviewStyle &previewStyle);
    int32_t UpdatePreviewStyleWithAnimation(const PreviewStyle &previewStyle, const PreviewAnimation &animation);
    int32_t RotateDragWindowSync(const std::shared_ptr<Rosen::RSTransaction>& rsTransaction = nullptr);
    int32_t GetDragSummary(std::map<std::string, int64_t> &summarys);
    int32_t EnterTextEditorArea(bool enable);
    int32_t GetDragAction(DragAction &dragAction);
    int32_t GetExtraInfo(std::string &extraInfo);
    int32_t AddPrivilege();
    int32_t EraseMouseIcon();
    int32_t SetDragWindowScreenId(uint64_t displayId, uint64_t screenId);
    int32_t AddSelectedPixelMap(std::shared_ptr<OHOS::Media::PixelMap> pixelMap, std::function<void(bool)> callback);

private:
    void InitClient();
    void InitMsgHandler();

    std::mutex mutex_;
    std::shared_ptr<TunnelClient> tunnel_ { nullptr };
    std::unique_ptr<SocketClient> client_ { nullptr };
    CooperateClient cooperate_;
    DragClient drag_;
    StationaryClient stationary_;
    bool isScreenRotation_ { false };
    std::vector<std::string> foldRotatePolicys_ {};
};

#define INTER_MGR_IMPL OHOS::Singleton<IntentionManager>::GetInstance()
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTENTION_MANAGER_H
