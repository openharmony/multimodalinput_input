/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PULL_THROW_SUBSCRIBER_HANDLER_H
#define PULL_THROW_SUBSCRIBER_HANDLER_H

#include <algorithm>
#include <atomic>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

#include "singleton.h"

#include "long_press_event.h"
#include "pointer_event.h"
#include "uds_server.h"


namespace OHOS {
namespace MMI {

class PullThrowSubscriberHandler final {
    DECLARE_DELAYED_SINGLETON(PullThrowSubscriberHandler);
public:
    DISALLOW_COPY_AND_MOVE(PullThrowSubscriberHandler);

    struct FingerGesture {
        struct {
            int32_t id { 0 };
            int32_t x { 0 };
            int32_t y { 0 };
            int64_t downTime { 0 };
        } touches[2];
    };
    
    void HandleFingerGestureDownEvent(std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGestureMoveEvent(std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGesturePullMoveEvent(std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGesturePullUpEvent(std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGestureUpEvent(std::shared_ptr<PointerEvent> touchEvent);
    int SetHotZoneArea(double locationX, double locationY, double width, double height);

private:
    void StopFingerGesture(std::shared_ptr<PointerEvent> touchEvent);
    void StartFingerGesture();
    bool CheckFingerValidation(std::shared_ptr<PointerEvent> touchEvent) const;
    bool CheckProgressValid(std::shared_ptr<PointerEvent> touchEvent);
    void UpdateFingerPoisition(std::shared_ptr<PointerEvent> touchEvent);
 
private:
    FingerGesture fingerGesture_;
    std::shared_ptr<PointerEvent> touchEvent_ { nullptr };
    bool gestureInProgress_ = false;
    double triggerTime_ = 0.0; // 触发时间，单位毫秒
    bool alreadyTouchDown_ = false;
    static constexpr double THRES_SPEED = 0.6; // 阈值，单位像素/秒
    static constexpr int64_t MIN_THRES_DIST = 100; // 阈值，单位像素
    static constexpr int32_t FIRST_TOUCH_FINGER = 0; // 最大手指数量
    const int64_t WINDOW_TIME_INTERVAL = 0.5e6; // 采样窗口，单位u秒
};
#define PULL_THROW_EVENT_HANDLER ::OHOS::DelayedSingleton<PullThrowSubscriberHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif  // PULL_THROW_SUBSCRIBER_HANDLER_H
