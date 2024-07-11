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

#ifndef INTENTION_DRAG_CLIENT_H
#define INTENTION_DRAG_CLIENT_H

#include "nocopyable.h"

#include <set>

#include "i_drag_listener.h"
#include "i_subscript_listener.h"
#include "i_tunnel_client.h"
#include "i_start_drag_listener.h"
#include "socket_client.h"
#include "transaction/rs_transaction.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DragClient final {
public:
    DragClient() = default;
    ~DragClient() = default;
    DISALLOW_COPY_AND_MOVE(DragClient);

    int32_t StartDrag(ITunnelClient &tunnel, const DragData &dragData, std::shared_ptr<IStartDragListener> listener);
    int32_t StopDrag(ITunnelClient &tunnel, const DragDropResult &dropResult);
    int32_t AddDraglistener(ITunnelClient &tunnel, DragListenerPtr listener);
    int32_t RemoveDraglistener(ITunnelClient &tunnel, DragListenerPtr listener);
    int32_t AddSubscriptListener(ITunnelClient &tunnel, SubscriptListenerPtr listener);
    int32_t RemoveSubscriptListener(ITunnelClient &tunnel, SubscriptListenerPtr listener);
    int32_t SetDragWindowVisible(ITunnelClient &tunnel, bool visible, bool isForce);
    int32_t UpdateDragStyle(ITunnelClient &tunnel, DragCursorStyle style);
    int32_t UpdateShadowPic(ITunnelClient &tunnel, const ShadowInfo &shadowInfo);
    int32_t GetDragTargetPid(ITunnelClient &tunnel);
    int32_t GetUdKey(ITunnelClient &tunnel, std::string &udKey);
    int32_t GetShadowOffset(ITunnelClient &tunnel, ShadowOffset &shadowOffset);
    int32_t GetDragData(ITunnelClient &tunnel, DragData &dragData);
    int32_t UpdatePreviewStyle(ITunnelClient &tunnel, const PreviewStyle &previewStyle);
    int32_t UpdatePreviewStyleWithAnimation(ITunnelClient &tunnel,
        const PreviewStyle &previewStyle, const PreviewAnimation &animation);
    int32_t RotateDragWindowSync(ITunnelClient &tunnel,
        const std::shared_ptr<Rosen::RSTransaction>& rsTransaction = nullptr);
    int32_t SetDragWindowScreenId(ITunnelClient &tunnel, uint64_t displayId, uint64_t screenId);
    int32_t GetDragSummary(ITunnelClient &tunnel, std::map<std::string, int64_t> &summary);
    int32_t GetDragState(ITunnelClient &tunnel, DragState &dragState);
    int32_t EnterTextEditorArea(ITunnelClient &tunnel, bool enable);
    int32_t GetDragAction(ITunnelClient &tunnel, DragAction &dragAction);
    int32_t GetExtraInfo(ITunnelClient &tunnel, std::string &extraInfo);
    int32_t AddPrivilege(ITunnelClient &tunnel);
    int32_t EraseMouseIcon(ITunnelClient &tunnel);
    int32_t AddSelectedPixelMap(ITunnelClient &tunnel, std::shared_ptr<OHOS::Media::PixelMap> pixelMap,
        std::function<void(bool)> callback);

    int32_t OnNotifyResult(const StreamClient &client, NetPacket &pkt);
    int32_t OnNotifyHideIcon(const StreamClient& client, NetPacket& pkt);
    int32_t OnStateChangedMessage(const StreamClient &client, NetPacket &pkt);
    int32_t OnDragStyleChangedMessage(const StreamClient &client, NetPacket &pkt);
    int32_t OnAddSelectedPixelMapResult(const StreamClient &client, NetPacket &pkt);

private:
    mutable std::mutex mtx_;
    std::shared_ptr<IStartDragListener> startDragListener_ { nullptr };
    bool hasRegistered_ { false };
    bool hasSubscriptRegistered_ { false };
    std::set<DragListenerPtr> dragListeners_;
    std::set<SubscriptListenerPtr> subscriptListeners_;
    std::function<void(bool)> addSelectedPixelMapCallback_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // INTENTION_DRAG_CLIENT_H
