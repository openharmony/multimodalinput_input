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

#include <chrono>
#include <condition_variable>
#include <functional>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "nocopyable.h"
#include "preferences.h"
#include "preferences_errno.h"
#include "preferences_helper.h"

#include "i_input_event_handler.h"
#include "key_event.h"
#include "struct_multimodal.h"

namespace OHOS {
namespace MMI {
enum KeyCommandType : int32_t {
    TYPE_SHORTKEY = 0,
    TYPE_SEQUENCE = 1,
    TYPE_FINGERSCENE = 2,
    TYPE_REPEAT_KEY = 3,
    TYPE_MULTI_FINGERS = 4,
};

enum class KnuckleType : int32_t {
    KNUCKLE_TYPE_SINGLE = 0,
    KNUCKLE_TYPE_DOUBLE = 1,
};

enum class NotifyType : int32_t {
    CANCEL,
    INCONSISTENTGESTURE,
    REGIONGESTURE,
    LETTERGESTURE,
    OTHER
};

struct Ability {
    std::string bundleName;
    std::string abilityName;
    std::string action;
    std::string type;
    std::string deviceId;
    std::string uri;
    std::string abilityType;
    std::vector<std::string> entities;
    std::map<std::string, std::string> params;
};

struct ShortcutKey {
    std::set<int32_t> preKeys;
    std::string businessId;
    std::string statusConfig;
    bool statusConfigValue { true };
    int32_t finalKey { -1 };
    int32_t keyDownDuration { 0 };
    int32_t triggerType { KeyEvent::KEY_ACTION_DOWN };
    int32_t timerId { -1 };
    Ability ability;
    void Print() const;
};

struct SequenceKey {
    int32_t keyCode { -1 };
    int32_t keyAction { 0 };
    int64_t actionTime { 0 };
    int64_t delay { 0 };
    bool operator!=(const SequenceKey &sequenceKey)
    {
        return (keyCode != sequenceKey.keyCode) || (keyAction != sequenceKey.keyAction);
    }
};

struct ExcludeKey {
    int32_t keyCode { -1 };
    int32_t keyAction { -1 };
    int64_t delay { 0 };
};

struct Sequence {
    std::vector<SequenceKey> sequenceKeys;
    std::string statusConfig;
    bool statusConfigValue { true };
    int64_t abilityStartDelay { 0 };
    int32_t timerId { -1 };
    Ability ability;
    friend std::ostream& operator<<(std::ostream&, const Sequence&);
};

struct TwoFingerGesture {
    inline static constexpr auto MAX_TOUCH_NUM = 2;
    bool active = false;
    int32_t timerId = -1;
    int64_t abilityStartDelay = 0;
    Ability ability;
    struct {
        int32_t id { 0 };
        int32_t x { 0 };
        int32_t y { 0 };
        int64_t downTime { 0 };
    } touches[MAX_TOUCH_NUM];
};

struct KnuckleGesture {
    std::shared_ptr<PointerEvent> lastPointerDownEvent { nullptr };
    bool state { false };
    int64_t lastPointerUpTime { 0 };
    int64_t downToPrevUpTime { 0 };
    float doubleClickDistance { 0.0f };
    Ability ability;
    struct {
        int32_t id { 0 };
        int32_t x { 0 };
        int32_t y { 0 };
    } lastDownPointer;
};

struct MultiFingersTap {
    Ability ability;
};

struct RepeatKey {
    int32_t keyCode { -1 };
    int32_t keyAction { 0 };
    int32_t times { 0 };
    int64_t actionTime { 0 };
    int64_t delay { 0 };
    std::string statusConfig;
    bool statusConfigValue { true };
    Ability ability;
};

struct KnuckleSwitch {
    std::string statusConfig { "" };
    bool statusConfigValue { false };
};

class KeyCommandHandler final : public IInputEventHandler {
public:
    KeyCommandHandler() = default;
    DISALLOW_COPY_AND_MOVE(KeyCommandHandler);
    ~KeyCommandHandler() override = default;
    int32_t UpdateSettingsXml(const std::string &businessId, int32_t delay);
    int32_t EnableCombineKey(bool enable);
    KnuckleGesture GetSingleKnuckleGesture() const;
    KnuckleGesture GetDoubleKnuckleGesture() const;
    void Dump(int32_t fd, const std::vector<std::string> &args);
    void PrintGestureInfo(int32_t fd);
    std::string ConvertKeyActionToString(int32_t keyAction);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
    void HandlePointerActionDownEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandlePointerActionMoveEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandlePointerActionUpEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void SetKnuckleDoubleTapIntervalTime(int64_t interval);
    void SetKnuckleDoubleTapDistance(float distance);
    bool GetKnuckleSwitchValue();
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    bool OnHandleEvent(const std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool OnHandleEvent(const std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef UNIT_TEST
public:
#else
private:
#endif // UNIT_TEST
    void Print();
    void PrintSeq();
    void PrintExcludeKeys();
    bool ParseConfig();
    bool ParseExcludeConfig();
    bool ParseJson(const std::string &configFile);
    bool ParseExcludeJson(const std::string &configFile);
    void ParseRepeatKeyMaxCount();
    void ParseStatusConfigObserver();
    void LaunchAbility(const Ability &ability);
    void LaunchAbility(const Ability &ability, int64_t delay);
    void LaunchAbility(const ShortcutKey &key);
    void LaunchAbility(const Sequence &sequence);
    bool IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key);
    bool IsRepeatKeyEvent(const SequenceKey &sequenceKey);
    bool HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey);
    bool HandleKeyDown(ShortcutKey &shortcutKey);
    bool HandleKeyCancel(ShortcutKey &shortcutKey);
    bool PreHandleEvent(const std::shared_ptr<KeyEvent> key);
    bool HandleEvent(const std::shared_ptr<KeyEvent> key);
    bool HandleKeyUpCancel(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleRepeatKeyCount(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleRepeatKey(const RepeatKey& item, bool &isLaunchAbility, const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleRepeatKeys(const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleSequence(Sequence& sequence, bool &isLaunchAbility);
    bool HandleNormalSequence(Sequence& sequence, bool &isLaunchAbility);
    bool HandleMatchedSequence(Sequence& sequence, bool &isLaunchAbility);
    bool HandleScreenLocked(Sequence& sequence, bool &isLaunchAbility);
    bool IsActiveSequenceRepeating(std::shared_ptr<KeyEvent> keyEvent) const;
    void MarkActiveSequence(bool active);
    bool HandleSequences(const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleShortKeys(const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleConsumedKeyEvent(const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleMulFingersTap(const std::shared_ptr<PointerEvent> pointerEvent);
    bool AddSequenceKey(const std::shared_ptr<KeyEvent> keyEvent);
    std::shared_ptr<KeyEvent> CreateKeyEvent(int32_t keyCode, int32_t keyAction, bool isPressed);
    bool IsEnableCombineKey(const std::shared_ptr<KeyEvent> key);
    bool IsExcludeKey(const std::shared_ptr<KeyEvent> key);
    void RemoveSubscribedTimer(int32_t keyCode);
    void HandleSpecialKeys(int32_t keyCode, int32_t keyAction);
    void InterruptTimers();
    void HandlePointerVisibleKeys(const std::shared_ptr<KeyEvent> &keyEvent);
    int32_t GetKeyDownDurationFromXml(const std::string &businessId);
    void SendKeyEvent();
    template <class T>
    void CreateStatusConfigObserver(T& item);
    void ResetLastMatchedKey()
    {
        lastMatchedKey_.preKeys.clear();
        lastMatchedKey_.finalKey = -1;
        lastMatchedKey_.timerId = -1;
        lastMatchedKey_.keyDownDuration = 0;
    }
    void ResetCurrentLaunchAbilityKey()
    {
        currentLaunchAbilityKey_.preKeys.clear();
        currentLaunchAbilityKey_.finalKey = -1;
        currentLaunchAbilityKey_.timerId = -1;
        currentLaunchAbilityKey_.keyDownDuration = 0;
    }

    void ResetSequenceKeys()
    {
        keys_.clear();
        filterSequences_.clear();
    }
    bool SkipFinalKey(const int32_t keyCode, const std::shared_ptr<KeyEvent> &key);

    void OnHandleTouchEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void StartTwoFingerGesture();
    void StopTwoFingerGesture();
    bool CheckTwoFingerGestureAction() const;
    bool CheckInputMethodArea(const std::shared_ptr<PointerEvent> touchEvent);
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleFingerGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandleFingerGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandleKnuckleGestureDownEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandleKnuckleGestureUpEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void SingleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent);
    void DoubleKnuckleGestureProcesser(const std::shared_ptr<PointerEvent> touchEvent);
    void ReportKnuckleScreenCapture(const std::shared_ptr<PointerEvent> touchEvent);
    void KnuckleGestureProcessor(std::shared_ptr<PointerEvent> touchEvent,
        KnuckleGesture &knuckleGesture, KnuckleType type);
    void UpdateKnuckleGestureInfo(const std::shared_ptr<PointerEvent> touchEvent, KnuckleGesture &knuckleGesture);
    void AdjustTimeIntervalConfigIfNeed(int64_t intervalTime);
    void AdjustDistanceConfigIfNeed(float distance);
    int32_t ConvertVPToPX(int32_t vp) const;
#endif // OHOS_BUILD_ENABLE_TOUCH
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
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    void CheckAndUpdateTappingCountAtDown(std::shared_ptr<PointerEvent> touchEvent);

private:
    Sequence matchedSequence_;
    ShortcutKey lastMatchedKey_;
    ShortcutKey currentLaunchAbilityKey_;
    std::map<std::string, ShortcutKey> shortcutKeys_;
    std::vector<Sequence> sequences_;
    std::vector<ExcludeKey> excludeKeys_;
    std::vector<Sequence> filterSequences_;
    std::vector<SequenceKey> keys_;
    std::vector<RepeatKey> repeatKeys_;
    std::vector<std::string> businessIds_;
    bool isParseConfig_ { false };
    bool isParseExcludeConfig_ { false };
    std::map<int32_t, int32_t> specialKeys_;
    std::map<int32_t, std::list<int32_t>> specialTimers_;
    TwoFingerGesture twoFingerGesture_;
    KnuckleGesture singleKnuckleGesture_;
    KnuckleGesture doubleKnuckleGesture_;
    MultiFingersTap threeFingersTap_;
    bool isTimeConfig_ { false };
    bool isDistanceConfig_ { false };
    bool isKnuckleSwitchConfig_ { false };
    struct KnuckleSwitch knuckleSwitch_;
    int32_t checkAdjustIntervalTimeCount_ { 0 };
    int32_t checkAdjustDistanceCount_ { 0 };
    int64_t downToPrevUpTimeConfig_ { 0 };
    float downToPrevDownDistanceConfig_ { 0.0f };
    float distanceDefaultConfig_ { 0.0f };
    float distanceLongConfig_ { 0.0f };
    bool enableCombineKey_ { true };
    RepeatKey repeatKey_;
    int32_t maxCount_ { 0 };
    int32_t count_ { 0 };
    int32_t repeatTimerId_ { -1 };
    int32_t knuckleCount_ { 0 };
    int64_t downActionTime_ { 0 };
    int64_t upActionTime_ { 0 };
    int32_t launchAbilityCount_ { 0 };
    int64_t intervalTime_ { 120000 };
    bool isDownStart_ { false };
    bool isKeyCancel_ { false };
    bool sequenceOccurred_ { false };
    bool isHandleSequence_ { false };
    bool isParseMaxCount_ { false };
    bool isParseStatusConfig_ { false };
    bool isDoubleClick_ { false };
    int32_t lastKeyEventCode_ { -1 };
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
#endif // OHOS_BUILD_ENABLE_GESTURESENSE_WRAPPER
    int64_t lastDownTime_ { 0 };
    int64_t previousUpTime_ { 0 };
    int32_t tappingCount_ { 0 };
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_COMMAND_HANDLER_H