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

#include "switch_subscriber_handler.h"

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
#define MMI_LOG_TAG "SwitchSubscriberHandler"

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void SwitchSubscriberHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void SwitchSubscriberHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void SwitchSubscriberHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_SWITCH
void SwitchSubscriberHandler::HandleSwitchEvent(const std::shared_ptr<SwitchEvent> switchEvent)
{
    CHKPV(switchEvent);
    if (OnSubscribeSwitchEvent(switchEvent)) {
        MMI_HILOGI("Subscribe switchEvent filter success. switchValue:%{public}d", switchEvent->GetSwitchValue());
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleSwitchEvent(switchEvent);
}
#endif // OHOS_BUILD_ENABLE_SWITCH

int32_t SwitchSubscriberHandler::SubscribeSwitchEvent(SessionPtr sess, int32_t subscribeId, int32_t switchType)
{
    CALL_INFO_TRACE;
    if (subscribeId < 0) {
        MMI_HILOGE("Invalid subscribeId");
        return RET_ERR;
    }
    if (switchType < SwitchEvent::SwitchType::SWITCH_DEFAULT) {
        MMI_HILOGE("Invalid switchType");
        return RET_ERR;
    }
    CHKPR(sess, ERROR_NULL_POINTER);

    MMI_HILOGD("subscribeId:%{public}d, switchType:%{public}d", subscribeId, switchType);
    auto subscriber = std::make_shared<Subscriber>(subscribeId, sess, switchType);
    InsertSubScriber(std::move(subscriber));
    InitSessionDeleteCallback();
    return RET_OK;
}

int32_t SwitchSubscriberHandler::UnsubscribeSwitchEvent(SessionPtr sess, int32_t subscribeId)
{
    CALL_INFO_TRACE;
    MMI_HILOGD("subscribeId:%{public}d", subscribeId);
    for (auto it = subscribers_.begin(); it != subscribers_.end(); ++it) {
        if ((*it)->id_ == subscribeId && (*it)->sess_ == sess) {
            subscribers_.erase(it);
            return RET_OK;
        }
    }
    MMI_HILOGE("UnsubscribeSwitchEvent failed with %{public}d", subscribeId);
    return RET_ERR;
}

bool SwitchSubscriberHandler::OnSubscribeSwitchEvent(std::shared_ptr<SwitchEvent> switchEvent)
{
    CHKPF(switchEvent);
    MMI_HILOGD("switchValue:%{public}d", switchEvent->GetSwitchValue());

    if (switchEvent->GetSwitchType() == SwitchEvent::SwitchType::SWITCH_LID) {
        DfxHisysevent::OnLidSwitchChanged(switchEvent->GetSwitchValue());
    }

    bool handled = false;
    for (const auto &subscriber : subscribers_) {
        if (subscriber->switchType_ == switchEvent->GetSwitchType() ||
            (subscriber->switchType_ == SwitchEvent::SwitchType::SWITCH_DEFAULT &&
                switchEvent->GetSwitchType() != SwitchEvent::SwitchType::SWITCH_PRIVACY)) {
            NotifySubscriber(switchEvent, subscriber);
            handled = true;
        }
    }
    MMI_HILOGD("%{public}s", handled ? "true" : "false");
    return handled;
}

void SwitchSubscriberHandler::InsertSubScriber(std::shared_ptr<Subscriber> subs)
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

void SwitchSubscriberHandler::OnSessionDelete(SessionPtr sess)
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

void SwitchSubscriberHandler::NotifySubscriber(std::shared_ptr<SwitchEvent> switchEvent,
                                               const std::shared_ptr<Subscriber> &subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(switchEvent);
    CHKPV(subscriber);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_SWITCH);
    InputEventDataTransformation::SwitchEventToNetPacket(switchEvent, pkt);
    if (subscriber->sess_ == nullptr) {
        MMI_HILOGE("Subscriber's sess is null");
        return;
    }
    int32_t fd = subscriber->sess_->GetFd();
    pkt << fd << subscriber->id_;
    MMI_HILOGI("Notify subscriber id:%{public}d, switchValue:%{public}d, pid:%{public}d",
        subscriber->id_, switchEvent->GetSwitchValue(), subscriber->sess_->GetPid());
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write dispatch subscriber failed");
        return;
    }
    if (!udsServerPtr->SendMsg(fd, pkt)) {
        MMI_HILOGE("Leave, server dispatch subscriber failed");
    }
}

bool SwitchSubscriberHandler::InitSessionDeleteCallback()
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

void SwitchSubscriberHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CALL_DEBUG_ENTER;
    mprintf(fd, "Subscriber information:\t");
    mprintf(fd, "subscribers: count=%d", subscribers_.size());
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
