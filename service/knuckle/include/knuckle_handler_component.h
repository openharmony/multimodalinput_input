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

#ifndef KNUCKLE_HANDLER_COMPONENT_H
#define KNUCKLE_HANDLER_COMPONENT_H

#include "i_knuckle_handler.h"

namespace OHOS {
namespace MMI {
class KnuckleHandlerComponent {
public:
    static KnuckleHandlerComponent &GetInstance();
    bool Init();

    void SetCurrentToolType(struct TouchType touchType, int32_t &toolType);
    void NotifyTouchUp(struct TouchType *rawTouch);
    void EnableFingersense(void);
    void DisableFingersense(void);
    void UpdateDisplayMode(int32_t displayMode);
    void SaveTouchInfo(float pointX, float pointY, int32_t toolType);
    int32_t CheckKnuckleEvent(float pointX, float pointY, bool &isKnuckleType);
    void SetMultiWindowScreenId(uint64_t screenId, uint64_t displayModeScreenId);
    void HandleKnuckleEvent(std::shared_ptr<PointerEvent> touchEvent);
    void RegisterSwitchObserver();
    int32_t RegisterKnuckleSwitchByUserId(int32_t userId);
    int32_t SetKnucklePermissions(int32_t permissions, bool enable);
    bool SkipKnuckleDetect();
    int32_t SetKnuckleSwitch(bool knuckleSwitch);
    void Dump(int32_t fd);
private:
    DISALLOW_COPY_AND_MOVE(KnuckleHandlerComponent);
    KnuckleHandlerComponent() = default;
    ~KnuckleHandlerComponent() = default;

    IKnuckleHandler *Load();
    bool LoadKnuckleSharedLibrary();
    void Unload();

private:
    using GetKnuckleHandlerFunc = IKnuckleHandler*(*)(const std::shared_ptr<IKnuckleContext>&);
    using DestroyKnuckleHandlerFunc = void(*)(IKnuckleHandler*);

    void *handle_ { nullptr };
    GetKnuckleHandlerFunc create_ { nullptr };
    DestroyKnuckleHandlerFunc destroy_ { nullptr };
    IKnuckleHandler *impl_ { nullptr };
};

class KnuckleContextImpl : public IKnuckleContext {
public:
    ~KnuckleContextImpl() = default;

    const OLD::DisplayInfo *GetPhysicalDisplay(int32_t id) override;
    std::optional<WindowInfo> GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId) override;

    void ReportKnuckleClickEvent() override;
    void ReportFailIfOneSuccTwoFail(std::shared_ptr<PointerEvent> touchEvent) override;
    void ReportFailIfKnockTooFast() override;
    void ReportSingleKnuckleDoubleClickEvent(int32_t intervalTime, int32_t distanceInterval) override;
    void ReportScreenRecorderGesture(int32_t intervalTime) override;
    void ReportFailIfInvalidTime(const std::shared_ptr<PointerEvent> touchEvent, int32_t intervalTime) override;
    void ReportFailIfInvalidDistance(const std::shared_ptr<PointerEvent> touchEvent, float distance) override;
    void ReportScreenCaptureGesture() override;
    void ReportKnuckleGestureFaildTimes() override;
    void ReportKnuckleGestureTrackLength(int32_t knuckleGestureTrackLength) override;
    void ReportKnuckleGestureTrackTime(const std::vector<int64_t> &gestureTimeStamps) override;
    void ReportKnuckleGestureFromSuccessToFailTime(int32_t intervalTime) override;
    void ReportSmartShotSuccTimes() override;
    void ReportKnuckleDrawSSuccessTimes() override;
    void ReportKnuckleGestureFromFailToSuccessTime(int32_t intervalTime) override;

    std::string GetBundleName(const std::string &key) override;
    void LaunchAbility(const Ability &ability, int64_t delay) override;
    int32_t SyncKnuckleStatus(bool isKnuckleEnable) override;
    bool UpdateDisplayId(int32_t &displayId) override;
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_HANDLER_COMPONENT_H