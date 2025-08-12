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

#ifndef LONG_PRESS_SUBSCRIBER_HANDLER_H
#define LONG_PRESS_SUBSCRIBER_HANDLER_H

#include "singleton.h"

#include "json_parser.h"
#include "long_press_event.h"
#include "pointer_event.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
struct DurationTimer {
    int32_t duration = -1;
    int32_t timerId = -1;
};

struct FingerGesture {
    inline static constexpr auto MAX_TOUCH_NUM = 2;
    struct {
        int32_t id { 0 };
        int32_t x { 0 };
        int32_t y { 0 };
        int64_t downTime { 0 };
    } touches[MAX_TOUCH_NUM];
};

struct Subscriber {
    Subscriber(int32_t id, SessionPtr sess, int32_t fingerCount, int32_t duration)
        : id_(id), sess_(sess), fingerCount_(fingerCount), duration_(duration) {}
    int32_t id_ { -1 };
    SessionPtr sess_ { nullptr };
    int32_t fingerCount_ { -1 };
    int32_t duration_ {-1};
};

class LongPressSubscriberHandler final {
    DECLARE_DELAYED_SINGLETON(LongPressSubscriberHandler);
public:
    DISALLOW_COPY_AND_MOVE(LongPressSubscriberHandler);
    
    int32_t SubscribeLongPressEvent(SessionPtr sess, int32_t subscribeId, const LongPressRequest &longPressRequest);
    int32_t UnsubscribeLongPressEvent(SessionPtr sess, int32_t subscribeId);
    void HandleFingerGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGestureMoveEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent);
    int32_t GetBundleName(std::string &bundleName, int32_t windowPid) const;

private:
    void OnSubscribeLongPressEvent(int32_t fingerCount, int32_t duration);
    void OnSubscribeLongPressCancelEvent(SessionPtr sess, int32_t fingerCount, int32_t duration) const;
    void NotifySubscriber(std::shared_ptr<Subscriber> subscriber, int32_t result) const;
    void OnSessionDelete(SessionPtr sess);
    void InsertSubScriber(const std::shared_ptr<Subscriber> subscriber);
    bool InitSessionDeleteCallback();
    void StopFingerGesture();
    int32_t ConvertVPToPX(int32_t vp) const;
    bool CheckFingerGestureAction(int32_t fingerCount) const;
    void StartFingerGesture(int32_t fingerCount);
    void AddDurationTimer(int32_t duration);
    void RemoveDurationTimer(int32_t fingerCount, int32_t duration);
    void AddSessSubscriber(const std::shared_ptr<Subscriber> subscriber);
    void RemoveSessSubscriber(SessionPtr sess, int32_t subscribeId);
    void CheckFingerGestureCancelEvent(const std::shared_ptr<PointerEvent> touchEvent) const;

private:
    std::map<std::pair<int32_t, int32_t>, std::vector<std::shared_ptr<Subscriber>>> subscriberInfos_;
    std::vector<DurationTimer> durationTimers_;
    std::map<SessionPtr, std::vector<std::shared_ptr<Subscriber>>> sessManager_;
    FingerGesture fingerGesture_;
    std::shared_ptr<PointerEvent> touchEvent_ { nullptr };
    std::atomic_bool callbackInitialized_ { false };
    bool isAllTimerClosed = false;
};
#define LONG_PRESS_EVENT_HANDLER ::OHOS::DelayedSingleton<LongPressSubscriberHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // LONG_PRESS_SUBSCRIBER_HANDLER_H
