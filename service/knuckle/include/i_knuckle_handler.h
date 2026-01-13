/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License") = 0;
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

#ifndef I_KNUCKLE_HANDLER_H
#define I_KNUCKLE_HANDLER_H

#include "knuckle_type.h"
#include "pointer_event.h"
#include "old_display_info.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
struct Ability;
class IKnuckleHandler {
public:
    IKnuckleHandler() = default;
    virtual ~IKnuckleHandler() = default;

    virtual void SetCurrentToolType(const struct TouchType &touchType, int32_t &toolType) = 0;
    virtual void NotifyTouchUp(struct TouchType *rawTouch) = 0;
    virtual void EnableFingersense(void) = 0;
    virtual void DisableFingersense(void) = 0;
    virtual void UpdateDisplayMode(int32_t displayMode) = 0;
    virtual void SaveTouchInfo(float pointX, float pointY, int32_t toolType) = 0;
    virtual int32_t CheckKnuckleEvent(float pointX, float pointY, bool &isKnuckleType) = 0;
    virtual void SetMultiWindowScreenId(uint64_t screenId, uint64_t displayModeScreenId) = 0;
    virtual void HandleKnuckleEvent(std::shared_ptr<PointerEvent> touchEvent) = 0;
    virtual void RegisterSwitchObserver() = 0;
    virtual int32_t RegisterKnuckleSwitchByUserId(int32_t userId) = 0;
    virtual int32_t SetKnucklePermissions(uint32_t permissions, bool enable) = 0;
    virtual bool SkipKnuckleDetect() = 0;
    virtual int32_t SetKnuckleSwitch(bool knuckleSwitch) = 0;
    virtual void Dump(int32_t fd) = 0;
};

class IKnuckleContext {
public:
    IKnuckleContext() = default;
    virtual ~IKnuckleContext() = default;

    virtual const OLD::DisplayInfo *GetPhysicalDisplay(int32_t id) = 0;
    virtual std::optional<WindowInfo> GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId) = 0;

    virtual void ReportKnuckleClickEvent() = 0;
    virtual void ReportFailIfOneSuccTwoFail(std::shared_ptr<PointerEvent> touchEvent) = 0;
    virtual void ReportFailIfKnockTooFast() = 0;
    virtual void ReportSingleKnuckleDoubleClickEvent(int32_t intervalTime, int32_t distanceInterval) = 0;
    virtual void ReportScreenRecorderGesture(int32_t intervalTime) = 0;
    virtual void ReportFailIfInvalidTime(const std::shared_ptr<PointerEvent> touchEvent, int32_t intervalTime) = 0;
    virtual void ReportFailIfInvalidDistance(const std::shared_ptr<PointerEvent> touchEvent, float distance) = 0;
    virtual void ReportScreenCaptureGesture() = 0;
    virtual void ReportKnuckleGestureFaildTimes() = 0;
    virtual void ReportKnuckleGestureTrackLength(int32_t knuckleGestureTrackLength) = 0;
    virtual void ReportKnuckleGestureTrackTime(const std::vector<int64_t> &gestureTimeStamps) = 0;
    virtual void ReportKnuckleGestureFromSuccessToFailTime(int32_t intervalTime) = 0;
    virtual void ReportSmartShotSuccTimes() = 0;
    virtual void ReportKnuckleDrawSSuccessTimes() = 0;
    virtual void ReportKnuckleGestureFromFailToSuccessTime(int32_t intervalTime) = 0;

    virtual std::string GetBundleName(const std::string &key) = 0;
    virtual void LaunchAbility(const Ability &ability, int64_t delay) = 0;
    virtual int32_t SyncKnuckleStatus(bool isKnuckleEnable) = 0;
    virtual bool UpdateDisplayId(int32_t &displayId) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // I_KNUCKLE_HANDLER_H