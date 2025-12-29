/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef KEY_COMMAND_HANDLER_H
#define KEY_COMMAND_HANDLER_H

#include "old_display_info.h"

#include "i_input_event_handler.h"
#include "input_handler_type.h"
#include <mutex>

#include "i_key_command_service.h"
#include "short_key_handler.h"
#include "sequence_key_handler.h"
#include "repeat_key_handler.h"
#include "key_command_context.h"
#include "key_command_types.h"
#include "key_config_parser.h"
#include "two_finger_gesture_handler.h"

namespace OHOS {
namespace MMI {
using MistouchPreventionCallbackFunc = std::function<void(int32_t)>;
class IMistouchPrevention  {
public:
    IMistouchPrevention() = default;
    virtual ~IMistouchPrevention() = default;

    virtual int32_t MistouchPreventionConnector(MistouchPreventionCallbackFunc callbackFunc) = 0;

    virtual int32_t MistouchPreventionClose() = 0;
};

class KeyCommandHandler final : public IInputEventHandler,
                                public std::enable_shared_from_this<KeyCommandHandler>,
                                public IKeyCommandService { // 实现这个接口，共享的方法放在接口中
public:
    KeyCommandHandler();
    DISALLOW_COPY_AND_MOVE(KeyCommandHandler);
    ~KeyCommandHandler() override;
    int32_t UpdateSettingsXml(const std::string &businessId, int32_t delay);
    int32_t EnableCombineKey(bool enable);
    KnuckleGesture GetSingleKnuckleGesture() const;
    KnuckleGesture GetDoubleKnuckleGesture() const;
    void Dump(int32_t fd, const std::vector<std::string> &args);
    void PrintGestureInfo(int32_t fd);
    std::string ConvertKeyActionToString(int32_t keyAction);
    int32_t RegisterKnuckleSwitchByUserId(int32_t userId);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
    void HandlePointerActionDownEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandlePointerActionUpEvent(const std::shared_ptr<PointerEvent> touchEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
    void SetKnuckleDoubleTapDistance(float distance);
    bool GetKnuckleSwitchValue();
    bool SkipKnuckleDetect();
    bool CheckInputMethodArea(const std::shared_ptr<PointerEvent> touchEvent);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    bool OnHandleEvent(const std::shared_ptr<KeyEvent> keyEvent);
    int32_t SetIsFreezePowerKey(const std::string pageName);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool OnHandleEvent(const std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void InitKeyObserver();
    bool PreHandleEvent();
    int32_t SetKnuckleSwitch(bool knuckleSwitch);
    void RegisterProximitySensor();
    void UnregisterProximitySensor();
    int32_t LaunchAiScreenAbility(int32_t pid);
    int32_t SwitchScreenCapturePermission(uint32_t permissionType, bool enable);
#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    void UnregisterMistouchPrevention() override;
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    uint32_t GetScreenCapturePermission() override;

private:
    bool ParseKnuckleConfig();
    bool ParseKnuckleJson(const std::string &configFile);
    void ParseRepeatKeyMaxCount();
    void ParseStatusConfigObserver();
    bool PreHandleEvent(const std::shared_ptr<KeyEvent> key);
    bool HandleEvent(const std::shared_ptr<KeyEvent> key);
    bool HandleMulFingersTap(const std::shared_ptr<PointerEvent> pointerEvent);
    bool IsEnableCombineKey(const std::shared_ptr<KeyEvent> key);
    bool IsExcludeKey(const std::shared_ptr<KeyEvent> key);
    void HandleSpecialKeys(int32_t keyCode, int32_t keyAction) override;
    void HandlePointerVisibleKeys(const std::shared_ptr<KeyEvent> &keyEvent);

    template <class T>
    void CreateStatusConfigObserver(T& item);
    bool GetKnuckleSwitchStatus(const std::string& key, const std::string &strUri, bool defaultValue);
    void CreateKnuckleConfigObserver(KnuckleSwitch& item);

#ifdef OHOS_BUILD_ENABLE_TOUCH
    void OnHandleTouchEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void InitializeLongPressConfigurations();
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    void HandleKnuckleGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandleKnuckleGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent);
    std::pair<int32_t, int32_t> CalcDrawCoordinate(const OLD::DisplayInfo& displayInfo,
        PointerEvent::PointerItem pointerItem);
    void SingleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent);
    void DoubleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent);
    void ReportKnuckleScreenCapture(const std::shared_ptr<PointerEvent> touchEvent);
    void KnuckleGestureProcessor(std::shared_ptr<PointerEvent> touchEvent,
        KnuckleGesture &knuckleGesture, KnuckleType type);
    void UpdateKnuckleGestureInfo(const std::shared_ptr<PointerEvent> touchEvent, KnuckleGesture &knuckleGesture);
    void AdjustDistanceConfigIfNeed(float distance);
    bool CheckKnuckleCondition(std::shared_ptr<PointerEvent> touchEvent);
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    void HandleKnuckleGestureEvent(std::shared_ptr<PointerEvent> touchEvent);
    void HandleKnuckleGestureTouchDown(std::shared_ptr<PointerEvent> touchEvent);
    void HandleKnuckleGestureTouchMove(std::shared_ptr<PointerEvent> touchEvent);
    void HandleKnuckleGestureTouchUp(std::shared_ptr<PointerEvent> touchEvent);
    void ProcessKnuckleGestureTouchUp(NotifyType type);
    void ResetKnuckleGesture();
    std::string GesturePointsToStr() const;
    bool IsValidAction(int32_t action);
    void ReportIfNeed();
    void ReportRegionGesture();
    void ReportLetterGesture();
    void ReportGestureInfo();
    bool IsMatchedAbility(std::vector<float> gesturePoints_, float gestureLastX, float gestureLastY);
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    void CheckAndUpdateTappingCountAtDown(std::shared_ptr<PointerEvent> touchEvent);
    bool TouchPadKnuckleDoubleClickHandle(std::shared_ptr<KeyEvent> event);
    void TouchPadKnuckleDoubleClickProcess(const std::string bundleName, const std::string abilityName,
        const std::string action);
    void SendNotSupportMsg(std::shared_ptr<PointerEvent> touchEvent);
    bool CheckBundleName(const std::shared_ptr<PointerEvent> touchEvent);
    void OnKunckleSwitchStatusChange(const std::string switchName);
    bool HasScreenCapturePermission(uint32_t permissionType) override;
#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    void CallMistouchPrevention() override;
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    void InitParse();
    void InitParse(const std::string funcName, const std::shared_ptr<KeyEvent> key);
    void InitExcludeParse(const std::string funcName, const std::shared_ptr<KeyEvent> key);
    void HandleSosAbilityLaunched() override;
    void SetupSosDelayTimer() override;
    void ClearSpecialKeys() override;
    void ResetLaunchAbilityCount() override;
    void ClearRepeatKeyCountMap() override;
    int32_t GetRetValue() override;
    void InitHandlers();

private:
    KeyCommandContext context_;
    std::unique_ptr<ShortKeyHandler> shortkeyHandler_;
    std::unique_ptr<SequenceKeyHandler> sequenceHandler_;
    std::unique_ptr<RepeatKeyHandler> repeatKeyHandler_;
    std::unique_ptr<KeyConfigParser> configParser_;
    std::unique_ptr<TwoFingerGestureHandler> twoFingerGestureHandler_;

    std::map<std::string, ShortcutKey> shortcutKeys_;
    std::vector<Sequence> sequences_;
    std::vector<RepeatKey> repeatKeys_;
    std::vector<ExcludeKey> excludeKeys_;

private:
    bool isKnuckleParseConfig_ { false };
    std::set<std::string> appWhiteList_;
    KnuckleGesture singleKnuckleGesture_;
    KnuckleGesture doubleKnuckleGesture_;
    MultiFingersTap threeFingersTap_;
    bool isDistanceConfig_ { false };
    bool isKnuckleSwitchConfig_ { false };
    struct KnuckleSwitch screenshotSwitch_;
    struct KnuckleSwitch recordSwitch_;

    int32_t checkAdjustDistanceCount_ { 0 };
    int64_t downToPrevUpTimeConfig_ { 0 };
    float downToPrevDownDistanceConfig_ { 0.0f };
    float distanceDefaultConfig_ { 0.0f };
    float distanceLongConfig_ { 0.0f };
    bool enableCombineKey_ { true };

    int32_t knuckleCount_ { 0 };
    bool isParseMaxCount_ { false };
    bool isParseStatusConfig_ { false };
    bool isDoubleClick_ { false };
    int32_t lastKeyEventCode_ { -1 };
    std::string sessionKey_ { };
    bool isStartBase_ { false };
#ifdef OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    bool isGesturing_ { false };
    bool isLetterGesturing_ { false };
    bool isLastGestureSucceed_ { false };
    float gestureLastX_ { 0.0f };
    float gestureLastY_ { 0.0f };
    float gestureTrackLength_ { 0.0f };
    std::vector<float> gesturePoints_;
    std::vector<int64_t> gestureTimeStamps_;
    int64_t drawOFailTimestamp_ { 0 };
    int64_t drawOSuccTimestamp_ { 0 };
    Direction lastDirection_ { DIRECTION0 };
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    int64_t lastDownTime_ { 0 };
    int64_t previousUpTime_ { 0 };
    int32_t tappingCount_ { 0 };
    std::mutex mutex_;
    std::map<int32_t, int64_t> lastPointerDownTime_;
    int64_t sosLaunchTime_ { -1 };
    int64_t powerUpTime_ { 0 };
    int32_t currentUserId_ { -1 };
    bool gameForbidFingerKnuckle_ { false };
    bool hasRegisteredSensor_ { false };
    uint32_t screenCapturePermission_ { ScreenCapturePermissionType::DEFAULT_PERMISSIONS };
    void *mistouchLibHandle_ {nullptr};
    IMistouchPrevention *mistouchPrevention_ {nullptr};
    std::atomic<int32_t> ret_ { 5 };
    std::mutex dataMutex_;
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_COMMAND_HANDLER_H