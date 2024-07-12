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

#include "hot_area.h"

#include "display_manager.h"

#include "devicestatus_define.h"

#undef LOG_TAG
#define LOG_TAG "HotArea"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
namespace {
constexpr int32_t HOT_AREA_WIDTH { 100 };
constexpr int32_t HOT_AREA_MARGIN { 200 };
}; // namespace

void HotArea::AddListener(const RegisterHotareaListenerEvent &event)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    HotAreaInfo info {
        .pid = event.pid,
        .msgId = MessageId::HOT_AREA_ADD_LISTENER,
    };
    auto [iter, isOk] = callbacks_.emplace(info);
    if (!isOk) {
        callbacks_.erase(iter);
        callbacks_.emplace(info);
    }
}

void HotArea::RemoveListener(const UnregisterHotareaListenerEvent &event)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    callbacks_.erase(HotAreaInfo { .pid = event.pid });
}

void HotArea::EnableCooperate(const EnableCooperateEvent &event)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    auto display = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    CHKPV(display);
    width_ = display->GetWidth();
    height_ = display->GetHeight();
}

int32_t HotArea::ProcessData(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(lock_);
    CHKPR(pointerEvent, RET_ERR);
    MMI::PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem)) {
        FI_HILOGE("Corrupted pointer event");
        return RET_ERR;
    }
    displayX_ = pointerItem.GetDisplayX();
    displayY_ = pointerItem.GetDisplayY();
    deltaX_ = pointerItem.GetRawDx();
    deltaY_ = pointerItem.GetRawDy();
    CheckInHotArea();
    CheckPointerToEdge(type_);
    NotifyMessage();
    return RET_OK;
}

void HotArea::CheckInHotArea()
{
    CALL_DEBUG_ENTER;
    if (displayX_ <= HOT_AREA_WIDTH && displayY_ >= HOT_AREA_MARGIN &&
        displayY_ <= (height_ - HOT_AREA_MARGIN)) {
        type_ = HotAreaType::AREA_LEFT;
    } else if (displayX_ >= (width_ - HOT_AREA_WIDTH) && displayY_ >= HOT_AREA_MARGIN &&
        displayY_ <= (height_ - HOT_AREA_MARGIN)) {
        type_ = HotAreaType::AREA_RIGHT;
    } else if (displayY_ <= HOT_AREA_WIDTH && displayX_ >= HOT_AREA_MARGIN &&
        displayX_ <= (width_ - HOT_AREA_MARGIN)) {
        type_ = HotAreaType::AREA_TOP;
    } else if (displayY_ >= (height_ - HOT_AREA_WIDTH) && displayX_ >= HOT_AREA_MARGIN &&
        displayX_ <= (width_ - HOT_AREA_MARGIN)) {
        type_ = HotAreaType::AREA_BOTTOM;
    } else {
        type_ = HotAreaType::AREA_NONE;
    }
}

void HotArea::CheckPointerToEdge(HotAreaType type)
{
    CALL_DEBUG_ENTER;
    if (type == HotAreaType::AREA_LEFT) {
        isEdge_ = displayX_ <= 0 && deltaX_ < 0;
    } else if (type == HotAreaType::AREA_RIGHT) {
        isEdge_ = displayX_ >= (width_ - 1) && deltaX_ > 0;
    } else if (type == HotAreaType::AREA_TOP) {
        isEdge_ = displayY_ <= 0 && deltaY_ < 0;
    } else if (type == HotAreaType::AREA_BOTTOM) {
        isEdge_ = displayY_ >= (height_ - 1) && deltaY_ > 0;
    } else {
        isEdge_ = false;
    }
}

void HotArea::NotifyMessage()
{
    CALL_DEBUG_ENTER;
    OnHotAreaMessage(type_, isEdge_);
}

void HotArea::OnHotAreaMessage(HotAreaType msg, bool isEdge)
{
    CALL_DEBUG_ENTER;
    for (const auto &callback : callbacks_) {
        NotifyHotAreaMessage(callback.pid, callback.msgId, msg, isEdge);
    }
}

void HotArea::OnClientDied(const ClientDiedEvent &event)
{
    FI_HILOGI("Remove client died listener, pid: %{public}d", event.pid);
    callbacks_.erase(HotAreaInfo { .pid = event.pid });
}

void HotArea::NotifyHotAreaMessage(int32_t pid, MessageId msgId, HotAreaType msg, bool isEdge)
{
    CALL_DEBUG_ENTER;
    CHKPV(env_);
    auto session = env_->GetSocketSessionManager().FindSessionByPid(pid);
    CHKPV(session);
    NetPacket pkt(msgId);

    pkt << displayX_ << displayY_ << static_cast<int32_t>(msg) << isEdge;
    if (pkt.ChkRWError()) {
        FI_HILOGE("Packet write data failed");
        return;
    }
    if (!session->SendMsg(pkt)) {
        FI_HILOGE("Sending failed");
        return;
    }
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
