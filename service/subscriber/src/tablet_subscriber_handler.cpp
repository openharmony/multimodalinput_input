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

#include "tablet_subscriber_handler.h"
#include <parameters.h>
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "net_packet.h"
#include "proto.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TabletSubscriberHandler"

namespace OHOS {
namespace MMI {
TabletSubscriberHandler::TabletSubscriberHandler() {}
TabletSubscriberHandler::~TabletSubscriberHandler() {}

void TabletSubscriberHandler::HandleTabletEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (OnSubscribeTabletProximity(pointerEvent)) {
        return;
    }
}

int32_t TabletSubscriberHandler::SubscribeTabletProximity(SessionPtr sess, int32_t subscribeId)
{
    CALL_INFO_TRACE;
    if (subscribeId < 0) {
        MMI_HILOGE("Invalid subscribeId");
        return RET_ERR;
    }
    CHKPR(sess, ERROR_NULL_POINTER);
    MMI_HILOGD("subscribeId:%{public}d", subscribeId);
    auto subscriber = std::make_shared<Subscriber>(subscribeId, sess);
    InsertSubScriber(std::move(subscriber));
    InitSessionDeleteCallback();
    return RET_OK;
}

int32_t TabletSubscriberHandler::UnsubscribetabletProximity(SessionPtr sess, int32_t subscribeId)
{
    CALL_INFO_TRACE;
    MMI_HILOGD("subscribeId:%{public}d", subscribeId);
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if ((*it)->id_ == subscribeId && (*it)->sess_ == sess) {
            subscribers_.erase(it);
            return RET_OK;
        }
    }
    MMI_HILOGE("UnsubscribeTabletEvent failed with %{public}d", subscribeId);
    return RET_ERR;
}

bool TabletSubscriberHandler::OnSubscribeTabletProximity(std::shared_ptr<PointerEvent> pointerevent)
{
    CHKPF(pointerevent);
    bool handled = false;
    for (const auto &subscriber : subscribers_) {
        if (pointerevent->GetPointerAction() == PointerEvent::POINTER_ACTION_PROXIMITY_IN ||
            pointerevent->GetPointerAction() == PointerEvent::POINTER_ACTION_PROXIMITY_OUT) {
            MMI_HILOGI("The subscriber:%{public}d", subscriber->sess_->GetPid());
            NotifySubscriber(pointerevent, subscriber);
            handled = true;
        }
    }
    MMI_HILOGD("%{public}s", handled ? "true" : "false");
    return handled;
}

void TabletSubscriberHandler::InsertSubScriber(std::shared_ptr<Subscriber> subs)
{
    CALL_DEBUG_ENTER;
    CHKPV(subs);
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if (subs->sess_ != nullptr && (*it)->id_ == subs->id_ && (*it)->sess_ == subs->sess_) {
            MMI_HILOGW("Repeat registration id:%{public}d, desc:%{public}s",
                subs->id_, subs->sess_->GetDescript().c_str());
            return;
        }
    }
    subscribers_.push_back(subs);
}

void TabletSubscriberHandler::OnSessionDelete(SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    CHKPV(sess);
    for (auto it = subscribers_.begin(); it != subscribers_.end();) {
        if ((*it)->sess_ == sess) {
            subscribers_.erase(it++);
            continue;
        }
        ++it;
    }
}

void TabletSubscriberHandler::NotifySubscriber(std::shared_ptr<PointerEvent> pointerEvent,
                                               const std::shared_ptr<Subscriber> &subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(pointerEvent);
    CHKPV(subscriber);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_TABLET);
    if (InputEventDataTransformation::Marshalling(pointerEvent, pkt) != RET_OK) {
        MMI_HILOGE("Marshalling pointer event failed, errCode:%{public}d", STREAM_BUF_WRITE_FAIL);
        return;
    }
    if (subscriber->sess_ == nullptr) {
        MMI_HILOGE("Subscriber's sess is null");
        return;
    }
    int32_t fd = subscriber->sess_->GetFd();
    pkt << fd << subscriber->id_;
    MMI_HILOGI("Notify subscriber id:%{public}d, pid:%{public}d",
        subscriber->id_, subscriber->sess_->GetPid());
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write dispatch subscriber failed");
        return;
    }
    if (!udsServerPtr->SendMsg(fd, pkt)) {
        MMI_HILOGE("Leave, server dispatch subscriber failed");
    }
}

bool TabletSubscriberHandler::InitSessionDeleteCallback()
{
    CALL_DEBUG_ENTER;
    if (callbackInitialized_) {
        MMI_HILOGD("Session delete callback has already been initialized");
        return true;
    }
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPF(udsServerPtr);
    std::function<void(SessionPtr)> callback =
        [this] (SessionPtr sess) { return this->OnSessionDelete(sess); };
    udsServerPtr->AddSessionDeletedCallback(callback);
    callbackInitialized_ = true;
    return true;
}

void TabletSubscriberHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Subscriber information:\t");
    mprintf(fd, "subscribers: count=%zu", subscribers_.size());
    for (const auto &item : subscribers_) {
        std::shared_ptr<Subscriber> subscriber = item;
        CHKPV(subscriber);
        SessionPtr session = item->sess_;
        CHKPV(session);
        mprintf(fd, "subscriber id:%d | Pid:%d | Uid:%d | Fd:%d\t",
                subscriber->id_, session->GetPid(), session->GetUid(), session->GetFd());
    }
}
} // namespace MMI
} // namespace OHOS
