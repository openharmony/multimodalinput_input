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

#include "drag_client.h"

#include "default_params.h"
#include "drag_params.h"
#include "devicestatus_define.h"
#include "proto.h"

#undef LOG_TAG
#define LOG_TAG "DragClient"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t DragClient::StartDrag(ITunnelClient &tunnel,
    const DragData &dragData, std::shared_ptr<IStartDragListener> listener)
{
    CALL_DEBUG_ENTER;
    CHKPR(listener, RET_ERR);
    if (dragData.shadowInfos.empty()) {
        FI_HILOGE("shadowInfos is empty");
        return ERR_INVALID_VALUE;
    }
    for (const auto& shadowInfo : dragData.shadowInfos) {
        CHKPR(shadowInfo.pixelMap, RET_ERR);
        if ((shadowInfo.x > 0) || (shadowInfo.y > 0) ||
            (shadowInfo.x < -shadowInfo.pixelMap->GetWidth()) ||
            (shadowInfo.y < -shadowInfo.pixelMap->GetHeight())) {
            FI_HILOGE("Invalid parameter, shadowInfox:%{public}d, shadowInfoy:%{public}d",
                shadowInfo.x, shadowInfo.y);
            return RET_ERR;
        }
    }
    if ((dragData.dragNum <= 0) || (dragData.buffer.size() > MAX_BUFFER_SIZE) ||
        (dragData.displayX < 0) || (dragData.displayY < 0)) {
        FI_HILOGE("Start drag, invalid argument, dragNum:%{public}d, bufferSize:%{public}zu, "
            "displayX:%{public}d, displayY:%{public}d",
            dragData.dragNum, dragData.buffer.size(), dragData.displayX, dragData.displayY);
        return RET_ERR;
    }
    {
        std::lock_guard<std::mutex> guard(mtx_);
        startDragListener_ = listener;
    }
    StartDragParam param { dragData };
    DefaultReply reply {};

    int32_t ret = tunnel.Start(Intention::DRAG, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::Start fail");
    }
    return ret;
}

int32_t DragClient::StopDrag(ITunnelClient &tunnel, const DragDropResult &dropResult)
{
    CALL_DEBUG_ENTER;
    StopDragParam param { dropResult };
    DefaultReply reply;

    int32_t ret = tunnel.Stop(Intention::DRAG, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::Start fail");
    }
    return ret;
}

int32_t DragClient::AddDraglistener(ITunnelClient &tunnel, DragListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    CHKPR(listener, RET_ERR);
    std::lock_guard<std::mutex> guard(mtx_);
    if (dragListeners_.find(listener) != dragListeners_.end()) {
        return RET_OK;
    }
    if (!hasRegistered_) {
        DefaultParam param {};
        DefaultReply reply {};
        FI_HILOGI("Start drag listening");

        int32_t ret = tunnel.AddWatch(Intention::DRAG, DragRequestID::ADD_DRAG_LISTENER, param, reply);
        if (ret != RET_OK) {
            FI_HILOGE("ITunnelClient::AddWatch fail");
            return ret;
        }
        hasRegistered_ = true;
    }
    dragListeners_.insert(listener);
    return RET_OK;
}

int32_t DragClient::RemoveDraglistener(ITunnelClient &tunnel, DragListenerPtr listener)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    if (listener == nullptr) {
        dragListeners_.clear();
    } else {
        dragListeners_.erase(listener);
    }
    if (hasRegistered_ && dragListeners_.empty()) {
        hasRegistered_ = false;
        DefaultParam param {};
        DefaultReply reply {};
        FI_HILOGI("Stop drag listening");

        int32_t ret = tunnel.RemoveWatch(Intention::DRAG, DragRequestID::REMOVE_DRAG_LISTENER, param, reply);
        if (ret != RET_OK) {
            FI_HILOGE("ITunnelClient::RemoveWatch fail");
            return ret;
        }
    }
    return RET_OK;
}

int32_t DragClient::AddSubscriptListener(ITunnelClient &tunnel, SubscriptListenerPtr listener)
{
    CHKPR(listener, RET_ERR);
    std::lock_guard<std::mutex> guard(mtx_);
    if (subscriptListeners_.find(listener) != subscriptListeners_.end()) {
        return RET_OK;
    }
    if (!hasSubscriptRegistered_) {
        DefaultParam param {};
        DefaultReply reply {};
        FI_HILOGI("Start subscript listening");

        int32_t ret = tunnel.AddWatch(Intention::DRAG, DragRequestID::ADD_SUBSCRIPT_LISTENER, param, reply);
        if (ret != RET_OK) {
            FI_HILOGE("ITunnelClient::AddWatch fail");
            return ret;
        }
        hasSubscriptRegistered_ = true;
    }
    subscriptListeners_.insert(listener);
    return RET_OK;
}

int32_t DragClient::RemoveSubscriptListener(ITunnelClient &tunnel, SubscriptListenerPtr listener)
{
    std::lock_guard<std::mutex> guard(mtx_);
    if (listener == nullptr) {
        subscriptListeners_.clear();
    } else {
        subscriptListeners_.erase(listener);
    }
    if (hasSubscriptRegistered_ && subscriptListeners_.empty()) {
        hasSubscriptRegistered_ = false;
        DefaultParam param {};
        DefaultReply reply {};
        FI_HILOGI("Stop subscript listening");

        int32_t ret = tunnel.RemoveWatch(Intention::DRAG, DragRequestID::REMOVE_SUBSCRIPT_LISTENER, param, reply);
        if (ret != RET_OK) {
            FI_HILOGE("ITunnelClient::RemoveWatch fail");
            return ret;
        }
    }
    return RET_OK;
}

int32_t DragClient::SetDragWindowVisible(ITunnelClient &tunnel, bool visible, bool isForce)
{
    SetDragWindowVisibleParam param { visible, isForce };
    DefaultReply reply {};

    int32_t ret = tunnel.SetParam(Intention::DRAG, DragRequestID::SET_DRAG_WINDOW_VISIBLE, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::SetParam fail");
    }
    return ret;
}

int32_t DragClient::UpdateDragStyle(ITunnelClient &tunnel, DragCursorStyle style)
{
    if ((style < DragCursorStyle::DEFAULT) || (style > DragCursorStyle::MOVE)) {
        FI_HILOGE("Invalid style:%{public}d", static_cast<int32_t>(style));
        return RET_ERR;
    }
    UpdateDragStyleParam param { style };
    DefaultReply reply {};

    int32_t ret = tunnel.SetParam(Intention::DRAG, DragRequestID::UPDATE_DRAG_STYLE, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::SetParam fail");
    }
    return ret;
}

int32_t DragClient::UpdateShadowPic(ITunnelClient &tunnel, const ShadowInfo &shadowInfo)
{
    CALL_DEBUG_ENTER;
    CHKPR(shadowInfo.pixelMap, RET_ERR);
    if ((shadowInfo.x > 0) || (shadowInfo.y > 0) ||
        (shadowInfo.x < -shadowInfo.pixelMap->GetWidth()) ||
        (shadowInfo.y < -shadowInfo.pixelMap->GetHeight())) {
        FI_HILOGE("Invalid parameter, shadowInfox:%{public}d, shadowInfoy:%{public}d",
            shadowInfo.x, shadowInfo.y);
        return RET_ERR;
    }
    UpdateShadowPicParam param { shadowInfo };
    DefaultReply reply {};

    int32_t ret = tunnel.SetParam(Intention::DRAG, DragRequestID::UPDATE_SHADOW_PIC, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::SetParam fail");
    }
    return ret;
}

int32_t DragClient::GetDragTargetPid(ITunnelClient &tunnel)
{
    CALL_DEBUG_ENTER;
    DefaultParam param {};
    GetDragTargetPidReply reply {};

    int32_t ret = tunnel.GetParam(Intention::DRAG, DragRequestID::GET_DRAG_TARGET_PID, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::GetParam fail");
        return -1;
    }
    return reply.targetPid_;
}

int32_t DragClient::GetUdKey(ITunnelClient &tunnel, std::string &udKey)
{
    DefaultParam param {};
    GetUdKeyReply reply {};

    int32_t ret = tunnel.GetParam(Intention::DRAG, DragRequestID::GET_UDKEY, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::GetParam fail");
        return ret;
    }
    udKey = reply.udKey_;
    FI_HILOGI("UdKey:%{public}s", reply.udKey_.c_str());
    return RET_OK;
}

int32_t DragClient::GetShadowOffset(ITunnelClient &tunnel, ShadowOffset &shadowOffset)
{
    DefaultParam param {};
    GetShadowOffsetReply reply {};

    int32_t ret = tunnel.GetParam(Intention::DRAG, DragRequestID::GET_SHADOW_OFFSET, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::GetParam fail");
        return ret;
    }
    shadowOffset = reply.shadowOffset_;
    return RET_OK;
}

int32_t DragClient::GetDragData(ITunnelClient &tunnel, DragData &dragData)
{
    CALL_DEBUG_ENTER;
    DefaultParam param {};
    GetDragDataReply reply { dragData };

    int32_t ret = tunnel.GetParam(Intention::DRAG, DragRequestID::GET_DRAG_DATA, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::GetParam fail");
    }
    return ret;
}

int32_t DragClient::UpdatePreviewStyle(ITunnelClient &tunnel, const PreviewStyle &previewStyle)
{
    UpdatePreviewStyleParam param { previewStyle };
    DefaultReply reply {};

    int32_t ret = tunnel.SetParam(Intention::DRAG, DragRequestID::UPDATE_PREVIEW_STYLE, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::SetParam fail");
    }
    return ret;
}

int32_t DragClient::UpdatePreviewStyleWithAnimation(ITunnelClient &tunnel,
    const PreviewStyle &previewStyle, const PreviewAnimation &animation)
{
    UpdatePreviewAnimationParam param { previewStyle, animation };
    DefaultReply reply {};

    int32_t ret = tunnel.SetParam(Intention::DRAG, DragRequestID::UPDATE_PREVIEW_STYLE_WITH_ANIMATION, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::SetParam fail");
    }
    return ret;
}

int32_t DragClient::RotateDragWindowSync(ITunnelClient &tunnel,
    const std::shared_ptr<Rosen::RSTransaction>& rsTransaction)
{
    RotateDragWindowSyncParam param { rsTransaction };
    DefaultReply reply {};

    int32_t ret = tunnel.Control(Intention::DRAG, DragRequestID::ROTATE_DRAG_WINDOW_SYNC, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::Control fail");
    }
    return ret;
}

int32_t DragClient::SetDragWindowScreenId(ITunnelClient &tunnel, uint64_t displayId, uint64_t screenId)
{
    SetDragWindowScreenIdParam param { displayId, screenId };
    DefaultReply reply {};

    int32_t ret = tunnel.SetParam(Intention::DRAG, DragRequestID::SET_DRAG_WINDOW_SCREEN_ID, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::SetParam fail");
    }
    return ret;
}

int32_t DragClient::GetDragSummary(ITunnelClient &tunnel, std::map<std::string, int64_t> &summary)
{
    DefaultParam param {};
    GetDragSummaryReply reply {};

    int32_t ret = tunnel.GetParam(Intention::DRAG, DragRequestID::GET_DRAG_SUMMARY, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::GetParam fail");
        return ret;
    }
    summary.swap(reply.summary_);
    return RET_OK;
}

int32_t DragClient::GetDragState(ITunnelClient &tunnel, DragState &dragState)
{
    DefaultParam param {};
    GetDragStateReply reply {};

    int32_t ret = tunnel.GetParam(Intention::DRAG, DragRequestID::GET_DRAG_STATE, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::GetParam fail");
        return ret;
    }
    dragState = reply.dragState_;
    return RET_OK;
}

int32_t DragClient::EnterTextEditorArea(ITunnelClient &tunnel, bool enable)
{
    EnterTextEditorAreaParam param { enable };
    DefaultReply reply {};

    int32_t ret = tunnel.Control(Intention::DRAG, DragRequestID::ENTER_TEXT_EDITOR_AREA, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::Control fail");
    }
    return ret;
}

int32_t DragClient::GetDragAction(ITunnelClient &tunnel, DragAction &dragAction)
{
    DefaultParam param {};
    GetDragActionReply reply {};

    int32_t ret = tunnel.GetParam(Intention::DRAG, DragRequestID::GET_DRAG_ACTION, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::GetParam fail");
        return ret;
    }
    dragAction = reply.dragAction_;
    return RET_OK;
}

int32_t DragClient::GetExtraInfo(ITunnelClient &tunnel, std::string &extraInfo)
{
    DefaultParam param {};
    GetExtraInfoReply reply {};

    int32_t ret = tunnel.GetParam(Intention::DRAG, DragRequestID::GET_EXTRA_INFO, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::GetParam fail");
        return ret;
    }
    extraInfo = std::move(reply.extraInfo_);
    return RET_OK;
}

int32_t DragClient::AddPrivilege(ITunnelClient &tunnel)
{
    DefaultParam param {};
    DefaultReply reply {};

    int32_t ret = tunnel.Control(Intention::DRAG, DragRequestID::ADD_PRIVILEGE, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::Control fail");
    }
    return ret;
}

int32_t DragClient::EraseMouseIcon(ITunnelClient &tunnel)
{
    DefaultParam param {};
    DefaultReply reply {};

    int32_t ret = tunnel.Control(Intention::DRAG, DragRequestID::ERASE_MOUSE_ICON, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::Control fail");
    }
    return ret;
}

int32_t DragClient::AddSelectedPixelMap(ITunnelClient &tunnel, std::shared_ptr<OHOS::Media::PixelMap> pixelMap,
    std::function<void(bool)> callback)
{
    CALL_DEBUG_ENTER;
    CHKPR(pixelMap, RET_ERR);
    CHKPR(callback, RET_ERR);
    std::lock_guard<std::mutex> guard(mtx_);
    addSelectedPixelMapCallback_ = callback;
    AddSelectedPixelMapParam param { pixelMap };
    DefaultReply reply {};

    int32_t ret = tunnel.SetParam(Intention::DRAG, DragRequestID::ADD_SELECTED_PIXELMAP, param, reply);
    if (ret != RET_OK) {
        FI_HILOGE("ITunnelClient::SetParam fail");
    }
    return ret;
}

int32_t DragClient::OnAddSelectedPixelMapResult(const StreamClient &client, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    bool result = false;

    pkt >> result;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet read addSelectedPixelMap msg failed");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    CHKPR(addSelectedPixelMapCallback_, RET_ERR);
    addSelectedPixelMapCallback_(result);
    return RET_OK;
}

int32_t DragClient::OnNotifyResult(const StreamClient &client, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    DragNotifyMsg notifyMsg;
    int32_t result = 0;
    int32_t dragBehavior = -1;
    pkt >> notifyMsg.displayX >> notifyMsg.displayY >> result >> notifyMsg.targetPid >> dragBehavior;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet read drag msg failed");
        return RET_ERR;
    }
    if ((result < static_cast<int32_t>(DragResult::DRAG_SUCCESS)) ||
        (result > static_cast<int32_t>(DragResult::DRAG_EXCEPTION))) {
        FI_HILOGE("Invalid result:%{public}d", result);
        return RET_ERR;
    }
    notifyMsg.result = static_cast<DragResult>(result);
    if ((dragBehavior < static_cast<int32_t>(DragBehavior::UNKNOWN)) ||
        (dragBehavior > static_cast<int32_t>(DragBehavior::MOVE))) {
        FI_HILOGE("Invalid dragBehavior:%{public}d", dragBehavior);
        return RET_ERR;
    }
    notifyMsg.dragBehavior = static_cast<DragBehavior>(dragBehavior);
    std::lock_guard<std::mutex> guard(mtx_);
    CHKPR(startDragListener_, RET_ERR);
    startDragListener_->OnDragEndMessage(notifyMsg);
    return RET_OK;
}

int32_t DragClient::OnNotifyHideIcon(const StreamClient& client, NetPacket& pkt)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    CHKPR(startDragListener_, RET_ERR);
    startDragListener_->OnHideIconMessage();
    return RET_OK;
}

int32_t DragClient::OnStateChangedMessage(const StreamClient &client, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    int32_t state = 0;
    pkt >> state;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet read drag msg failed");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    for (const auto &listener : dragListeners_) {
        listener->OnDragMessage(static_cast<DragState>(state));
    }
    return RET_OK;
}

int32_t DragClient::OnDragStyleChangedMessage(const StreamClient &client, NetPacket &pkt)
{
    CALL_DEBUG_ENTER;
    int32_t style = 0;
    pkt >> style;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet read drag msg failed");
        return RET_ERR;
    }
    std::lock_guard<std::mutex> guard(mtx_);
    for (const auto &listener : subscriptListeners_) {
        listener->OnMessage(static_cast<DragCursorStyle>(style));
    }
    return RET_OK;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
