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
#include "long_press_subscriber_handler.h"

#include "app_mgr_client.h"
#include "key_command_handler_util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "LongPressSubscriberHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t ONE_FINGER { 1 };
constexpr int32_t TWO_FINGER { 2 };
constexpr int32_t DEFAULT_USER_ID { 100 };
constexpr int32_t PX_BASE { 160 };
constexpr int32_t MS_TO_US { 1000 };

}
bool Compare(const std::shared_ptr<Subscriber> &a, const std::shared_ptr<Subscriber> &b)
{
    return a->duration_ < b->duration_;
}

LongPressSubscriberHandler::LongPressSubscriberHandler() {}

LongPressSubscriberHandler::~LongPressSubscriberHandler() {}

int32_t LongPressSubscriberHandler::SubscribeLongPressEvent(SessionPtr sess, int32_t subscribeId,
    const LongPressRequest &longPressRequest)
{
    CALL_DEBUG_ENTER;
    CHKPR(sess, ERROR_NULL_POINTER);
    MMI_HILOGD("SubscribeId:%{public}d, fingerCount:%{public}d, duration:%{public}d",
        subscribeId, longPressRequest.fingerCount, longPressRequest.duration);
    if (subscribeId < 0) {
        MMI_HILOGE("Invalid subscribeId");
        return RET_ERR;
    }

    AddDurationTimer(longPressRequest.duration);
    auto subscriber = std::make_shared<Subscriber>(subscribeId, sess, longPressRequest.fingerCount,
        longPressRequest.duration);

    AddSessSubscriber(subscriber);
    InsertSubScriber(std::move(subscriber));
    InitSessionDeleteCallback();
    return RET_OK;
}

int32_t LongPressSubscriberHandler::UnsubscribeLongPressEvent(SessionPtr sess, int32_t subscribeId)
{
    CALL_INFO_TRACE;
    CHKPR(sess, ERROR_NULL_POINTER);
    if (subscribeId < 0) {
        MMI_HILOGE("Invalid subscribeId:%{public}d", subscribeId);
        return RET_ERR;
    }

    for (auto it = subscriberInfos_.begin(); it != subscriberInfos_.end(); ++it) {
        std::vector<std::shared_ptr<Subscriber>> &subscribers = it->second;
        for (auto iter = subscribers.begin(); iter != subscribers.end(); ++iter) {
            if ((*iter)->sess_ == sess && (*iter)->id_ == subscribeId) {
                subscribers.erase(iter);
                auto fingerCount = it->first.first;
                auto duration = it->first.second;
                if (subscribers.empty()) {
                    subscriberInfos_.erase(it);
                }
                RemoveDurationTimer(fingerCount, duration);
                RemoveSessSubscriber(sess, subscribeId);
                MMI_HILOGD("UnsubscribeLongPressEvent successed with %{public}d", subscribeId);
                return RET_OK;
            }
        }
    }
    MMI_HILOGE("UnsubscribeLongPressEvent failed with %{public}d", subscribeId);
    return RET_ERR;
}

void LongPressSubscriberHandler::AddDurationTimer(int32_t duration)
{
    CALL_DEBUG_ENTER;
    bool isExist = false;
    for (auto &durationTimer : durationTimers_) {
        if (durationTimer.duration == duration) {
            isExist = true;
            break;
        }
    }
    if (!isExist) {
        DurationTimer durationTimer = {
            .duration = duration,
        };
        durationTimers_.push_back(durationTimer);
    }
}

void LongPressSubscriberHandler::RemoveDurationTimer(int32_t fingerCount, int32_t duration)
{
    CALL_DEBUG_ENTER;
    for (auto it = subscriberInfos_.begin(); it != subscriberInfos_.end(); ++it) {
        if (it->first.second == duration && !it->second.empty()) {
            return;
        }
    }
    for (auto timer = durationTimers_.begin(); timer != durationTimers_.end(); ++timer) {
        if (timer->duration == duration) {
            durationTimers_.erase(timer);
            return;
        }
    }
}

void LongPressSubscriberHandler::AddSessSubscriber(const std::shared_ptr<Subscriber> subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(subscriber);
    std::vector<std::shared_ptr<Subscriber>> &subscribers = sessManager_[subscriber->sess_];
    subscribers.insert(std::lower_bound(subscribers.begin(), subscribers.end(), subscriber, Compare), subscriber);
}

void LongPressSubscriberHandler::RemoveSessSubscriber(SessionPtr sess, int32_t subscribeId)
{
    CALL_DEBUG_ENTER;
    CHKPV(sess);
    auto it = sessManager_.find(sess);
    if (it == sessManager_.end()) {
        MMI_HILOGE("Not found the sess");
        return;
    }
    std::vector<std::shared_ptr<Subscriber>> &subscribers = it->second;
    for (auto iter = subscribers.begin(); iter != subscribers.end(); ++iter) {
        if ((*iter)->id_ == subscribeId) {
            subscribers.erase(iter);
            if (subscribers.empty()) {
                sessManager_.erase(it);
            }
            return;
        }
    }
}

void LongPressSubscriberHandler::OnSubscribeLongPressEvent(int32_t fingerCount, int32_t duration)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("FingerCount:%{public}d, duration:%{public}d", fingerCount, duration);
    auto pair = std::make_pair(fingerCount, duration);
    auto it = subscriberInfos_.find(pair);
    if (subscriberInfos_.find(pair) == subscriberInfos_.end()) {
        MMI_HILOGE("Not found the subscriber, fingerCount:%{public}d, duration:%{public}d",
            fingerCount, duration);
        return;
    }
    std::vector<std::shared_ptr<Subscriber>> &subscribers = it->second;
    for (const auto &subscriber : subscribers) {
        NotifySubscriber(subscriber, RET_OK);
    }
}

void LongPressSubscriberHandler::InsertSubScriber(const std::shared_ptr<Subscriber> subscriber)
{
    CALL_DEBUG_ENTER;
    CHKPV(subscriber);
    auto pair = std::make_pair(subscriber->fingerCount_, subscriber->duration_);
    auto it = subscriberInfos_.find(pair);
    if (it != subscriberInfos_.end()) {
        std::vector<std::shared_ptr<Subscriber>> &subscribers = it->second;
        for (const auto &sub : subscribers) {
            if (subscriber->sess_ != nullptr && sub->id_ == subscriber->id_ && sub->sess_ == subscriber->sess_) {
                MMI_HILOGW("Repeat registration id:%{public}d, desc:%{public}s",
                    subscriber->id_, subscriber->sess_->GetDescript().c_str());
                return;
            }
        }
    }
    subscriberInfos_[pair].push_back(subscriber);
}

void LongPressSubscriberHandler::OnSessionDelete(SessionPtr sess)
{
    CALL_DEBUG_ENTER;
    CHKPV(sess);
    for (auto it = subscriberInfos_.begin(); it != subscriberInfos_.end();) {
        std::vector<std::shared_ptr<Subscriber>> &subscribers = it->second;
        for (auto iter = subscribers.begin(); iter != subscribers.end();) {
            if ((*iter)->sess_ == sess) {
                RemoveSessSubscriber(sess, (*iter)->id_);
                iter = subscribers.erase(iter);
                auto fingerCount = it->first.first;
                auto duration = it->first.second;
                RemoveDurationTimer(fingerCount, duration);
                continue;
            }
            ++iter;
        }
        if (subscribers.empty()) {
            it = subscriberInfos_.erase(it);
        } else {
             ++it;
        }
    }
}

void LongPressSubscriberHandler::HandleFingerGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    auto fingerCount = touchEvent->GetPointerIds().size();
    if (fingerCount > 0 && fingerCount <= TwoFingerGesture::MAX_TOUCH_NUM) {
        touchEvent_ = touchEvent;
        int32_t id = touchEvent->GetPointerId();
        PointerEvent::PointerItem item;
        touchEvent->GetPointerItem(id, item);
        fingerGesture_.touches[fingerCount - 1].id = id;
        fingerGesture_.touches[fingerCount - 1].x = item.GetDisplayX();
        fingerGesture_.touches[fingerCount - 1].y = item.GetDisplayY();
        fingerGesture_.touches[fingerCount - 1].downTime = item.GetDownTime();
    } else {
        MMI_HILOGD("The number of finger count is not 1 or 2");
        return;
    }
    if (fingerCount == static_cast<size_t>(ONE_FINGER)) {
        StartFingerGesture(ONE_FINGER);
    } else if (fingerCount == static_cast<size_t>(TWO_FINGER)) {
        StopFingerGesture();
        auto firstFinger = fingerGesture_.touches[0];
        auto secondFinger = fingerGesture_.touches[1];
        auto pressTimeInterval = fabs(firstFinger.downTime - secondFinger.downTime);
        if (pressTimeInterval > TWO_FINGERS_TIME_LIMIT) {
            MMI_HILOGI("Two fingers time too long firstdownTime:%{public}" PRId64 ",seconddownTime:%{public}" PRId64,
                firstFinger.downTime, secondFinger.downTime);
            return;
        }
        StartFingerGesture(TWO_FINGER);
    } else {
        MMI_HILOGW("The number of finger count is not 1 or 2");
        StopFingerGesture();
    }
}

void LongPressSubscriberHandler::HandleFingerGestureMoveEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (isAllTimerClosed) {
        MMI_HILOGD("Finger gesture has stopped");
        return;
    }
    auto fingerCount = touchEvent->GetPointerIds().size();
    if (fingerCount > static_cast<size_t>(TWO_FINGER)) {
        MMI_HILOGE("Not support more than two finger gesture");
        return;
    }
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    auto pos = std::find_if(std::begin(fingerGesture_.touches), std::end(fingerGesture_.touches),
        [id](const auto& item) { return item.id == id; });
    if (pos == std::end(fingerGesture_.touches)) {
        MMI_HILOGE("Cant't find the pointer id");
        return;
    }
    auto dx = std::abs(pos->x - item.GetDisplayX());
    auto dy = std::abs(pos->y - item.GetDisplayY());
    auto moveDistance = sqrt(pow(dx, TWO_FINGER) + pow(dy, TWO_FINGER));
    if (moveDistance > TOUCH_MOVE_THRESHOLD) {
        MMI_HILOGD("Finger movement distance greater than 15PX, defaultDistance:%{public}d, moveDistance:%{public}f",
            TOUCH_MOVE_THRESHOLD, moveDistance);
        CheckFingerGestureCancelEvent(touchEvent);
        StopFingerGesture();
    }
}

void LongPressSubscriberHandler::HandleFingerGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    if (isAllTimerClosed) {
        MMI_HILOGD("Finger gesture has stopped");
        return;
    }
    if (touchEvent->GetPointerIds().size() > static_cast<size_t>(TWO_FINGER)) {
        MMI_HILOGE("Not support more than two finger gesture");
        return;
    }
    CheckFingerGestureCancelEvent(touchEvent);
    StopFingerGesture();
}

void LongPressSubscriberHandler::CheckFingerGestureCancelEvent(const std::shared_ptr<PointerEvent> touchEvent) const
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    auto fingerCount = touchEvent->GetPointerIds().size();
    size_t index = fingerCount - 1;
    if (index < 0 || index > static_cast<size_t>(ONE_FINGER)) {
        MMI_HILOGE("Not support more than two finger gesture");
        return;
    }
    int64_t currentTime = touchEvent->GetActionTime() - fingerGesture_.touches[index].downTime;
    if (!durationTimers_.empty()) {
        if (currentTime < durationTimers_[0].duration * MS_TO_US) {
            MMI_HILOGD("The current time is earlier than the minimum delay, the cancel event does not need to be sent");
            return;
        }
    }

    for (auto it = sessManager_.begin(); it != sessManager_.end(); ++it) {
        const std::vector<std::shared_ptr<Subscriber>> &subscribers = it->second;
        std::vector<std::shared_ptr<Subscriber>> tempSubs;
        for (auto iter = subscribers.begin(); iter != subscribers.end(); ++iter) {
            if (fingerCount == static_cast<size_t>((*iter)->fingerCount_)) {
                tempSubs.push_back(*iter);
            }
        }
        if (tempSubs.size() < static_cast<size_t>(TWO_FINGER)) {
            continue;
        }
        for (size_t i = 0; i + 1 < tempSubs.size(); ++i) {
            if (currentTime < (tempSubs[i]->duration_ * MS_TO_US)) {
                break;
            }
            if ((currentTime > (tempSubs[i]->duration_ * MS_TO_US)) &&
                (currentTime < (tempSubs[i + 1]->duration_ * MS_TO_US))) {
                OnSubscribeLongPressCancelEvent(it->first, fingerCount, tempSubs[i + 1]->duration_);
                break;
            }
        }
    }
}

void LongPressSubscriberHandler::OnSubscribeLongPressCancelEvent(SessionPtr sess, int32_t fingerCount,
    int32_t duration) const
{
    CALL_DEBUG_ENTER;
    auto it = sessManager_.find(sess);
    if (it == sessManager_.end()) {
        MMI_HILOGE("Not found the sess");
        return;
    }
    const std::vector<std::shared_ptr<Subscriber>> &subscribers = sessManager_.at(sess);
    for (const auto &subscriber : subscribers) {
        if (subscriber->fingerCount_ == fingerCount && subscriber->duration_ == duration) {
            NotifySubscriber(subscriber, RET_ERR);
        }
    }
}

void LongPressSubscriberHandler::StartFingerGesture(int32_t fingerCount)
{
    CALL_DEBUG_ENTER;
    for (size_t i = 0; i < durationTimers_.size(); ++i) {
        durationTimers_[i].timerId = TimerMgr->AddTimer(durationTimers_[i].duration, 1, [this, i, fingerCount]() {
            durationTimers_[i].timerId = -1;
            if (!CheckFingerGestureAction(fingerCount)) {
                return;
            }
            OnSubscribeLongPressEvent(fingerCount, durationTimers_[i].duration);
        });
    }
    isAllTimerClosed = false;
}

void LongPressSubscriberHandler::StopFingerGesture()
{
    CALL_DEBUG_ENTER;
    for (auto &durationTimer : durationTimers_) {
        if (durationTimer.timerId != -1) {
            TimerMgr->RemoveTimer(durationTimer.timerId);
            durationTimer.timerId = -1;
        }
    }
    isAllTimerClosed = true;
}

bool LongPressSubscriberHandler::CheckFingerGestureAction(int32_t fingerCount) const
{
    CALL_DEBUG_ENTER;
    auto displayInfo = WIN_MGR->GetDefaultDisplayInfo();
    CHKPR(displayInfo, false);
    auto leftLimit = ConvertVPToPX(TOUCH_LIFT_LIMIT);
    auto rightLimit = displayInfo->width - ConvertVPToPX(TOUCH_RIGHT_LIMIT);
    auto topLimit = ConvertVPToPX(TOUCH_TOP_LIMIT);
    auto bottomLimit = displayInfo->height - ConvertVPToPX(TOUCH_BOTTOM_LIMIT);

    auto firstFinger = fingerGesture_.touches[0];
    if (firstFinger.x <= leftLimit || firstFinger.x >= rightLimit ||
        firstFinger.y <= topLimit || firstFinger.y >= bottomLimit) {
        MMI_HILOGI("Any finger out of region");
        return false;
    }
    if (fingerCount == TWO_FINGER) {
        auto secondFinger = fingerGesture_.touches[1];
        if (secondFinger.x <= leftLimit || secondFinger.x >= rightLimit ||
            secondFinger.y <= topLimit || secondFinger.y >= bottomLimit) {
            MMI_HILOGI("Any finger out of region");
            return false;
        }
        auto devX = firstFinger.x - secondFinger.x;
        auto devY = firstFinger.y - secondFinger.y;
        auto distance = sqrt(pow(devX, TWO_FINGER) + pow(devY, TWO_FINGER));
        if (distance < ConvertVPToPX(TWO_FINGERS_DISTANCE_LIMIT)) {
            MMI_HILOGI("Two fingers distance:%{public}f too small", distance);
            return false;
        }
    }
    return true;
}

bool LongPressSubscriberHandler::InitSessionDeleteCallback()
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

int32_t LongPressSubscriberHandler::ConvertVPToPX(int32_t vp) const
{
    if (vp <= 0) {
        return 0;
    }
    auto displayInfo = WIN_MGR->GetDefaultDisplayInfo();
    CHKPR(displayInfo, 0);
    int32_t dpi = displayInfo->dpi;
    if (dpi <= 0) {
        return 0;
    }
    return vp * (dpi / PX_BASE);
}

int32_t LongPressSubscriberHandler::GetBundleName(std::string &bundleName, int32_t windowPid) const
{
    CALL_DEBUG_ENTER;
    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    CHKPR(appMgrClient, ERROR_NULL_POINTER);
    int32_t userid = WIN_MGR->GetCurrentUserId();
    if (userid < 0) {
        userid = DEFAULT_USER_ID;
    }
    auto udsServer = InputHandler->GetUDSServer();
    CHKPR(udsServer, RET_ERR);
    auto sess = udsServer->GetSessionByPid(windowPid);
    if (sess != nullptr) {
        bundleName = sess->GetProgramName();
        return RET_OK;
    }
    return RET_ERR;
}

void LongPressSubscriberHandler::NotifySubscriber(std::shared_ptr<Subscriber> subscriber, int32_t result) const
{
    CALL_DEBUG_ENTER;
    CHKPV(subscriber);
    auto udsServerPtr = InputHandler->GetUDSServer();
    CHKPV(udsServerPtr);
    if (subscriber->sess_ == nullptr) {
        MMI_HILOGE("Subscriber's sess is null");
        return;
    }
    int32_t windowPid = WIN_MGR->GetWindowPid(touchEvent_->GetTargetWindowId());
    if (windowPid == RET_ERR) {
        MMI_HILOGE("Get window pid failed");
        return;
    }

    std::string bundleName;
    if (GetBundleName(bundleName, windowPid) == RET_ERR) {
        MMI_HILOGE("Failed to get bundle name, pid %{public}d", windowPid);
    }
    int32_t id = touchEvent_->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent_->GetPointerItem(id, item);
    LongPressEvent longPressEvent = {
        .fingerCount = subscriber->fingerCount_,
        .duration = subscriber->duration_,
        .pid = windowPid,
        .displayId = touchEvent_->GetTargetDisplayId(),
        .displayX = fingerGesture_.touches[0].x,
        .displayY = fingerGesture_.touches[0].y,
        .result = result,
        .windowId = touchEvent_->GetTargetWindowId(),
        .pointerId = touchEvent_->GetPointerId(),
        .downTime = item.GetDownTime(),
        .bundleName = bundleName,
    };

    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_LONG_PRESS);
    InputEventDataTransformation::LongPressEventToNetPacket(longPressEvent, pkt);
    int32_t fd = subscriber->sess_->GetFd();
    pkt << fd << subscriber->id_;
    MMI_HILOGI("Notify subscriber id:%{public}d, pid:%{public}d", subscriber->id_, subscriber->sess_->GetPid());
    if (pkt.ChkRWError()) {
        MMI_HILOGE("Packet write dispatch subscriber failed");
        return;
    }
    if (!udsServerPtr->SendMsg(fd, pkt)) {
        MMI_HILOGE("Leave, server dispatch subscriber failed");
    }
}
} // namespace MMI
} // namespace OHOS
