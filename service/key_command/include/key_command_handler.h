/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "i_input_event_handler.h"
#include "key_event.h"
#include "struct_multimodal.h"
#include "preferences.h"
#include "preferences_impl.h"
#include "preferences_errno.h"
#include "preferences_helper.h"
#include "preferences_xml_utils.h"

namespace OHOS {
namespace MMI {
struct Ability {
    std::string bundleName;
    std::string abilityName;
    std::string action;
    std::string type;
    std::string deviceId;
    std::string uri;
    std::vector<std::string> entities;
    std::map<std::string, std::string> params;
};

struct ShortcutKey {
    std::set<int32_t> preKeys;
    std::string businessId;
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

struct Sequence {
    std::vector<SequenceKey> sequenceKeys;
    int64_t abilityStartDelay { 0 };
    int32_t timerId { -1 };
    Ability ability;
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
    } touches[MAX_TOUCH_NUM];
};

class KeyCommandHandler final : public IInputEventHandler {
public:
    KeyCommandHandler() = default;
    DISALLOW_COPY_AND_MOVE(KeyCommandHandler);
    ~KeyCommandHandler() override = default;
    int32_t UpdateSettingsXml(const std::string &businessId, int32_t delay);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
    bool OnHandleEvent(const std::shared_ptr<KeyEvent> keyEvent);
private:
    void Print();
    void PrintSeq();
    bool ParseConfig();
    bool ParseJson(const std::string &configFile);
    void LaunchAbility(const Ability &ability, int64_t delay);
    void LaunchAbility(const ShortcutKey &key);
    void LaunchAbility(const Sequence &sequence);
    bool IsKeyMatch(const ShortcutKey &shortcutKey, const std::shared_ptr<KeyEvent> &key);
    bool IsRepeatKeyEvent(const SequenceKey &sequenceKey);
    bool HandleKeyUp(const std::shared_ptr<KeyEvent> &keyEvent, const ShortcutKey &shortcutKey);
    bool HandleKeyDown(ShortcutKey &shortcutKey);
    bool HandleKeyCancel(ShortcutKey &shortcutKey);
    bool HandleSequence(Sequence& sequence, bool &isLaunchAbility);
    bool HandleSequences(const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleShortKeys(const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleConsumedKeyEvent(const std::shared_ptr<KeyEvent> keyEvent);
    bool AddSequenceKey(const std::shared_ptr<KeyEvent> keyEvent);
    void RemoveSubscribedTimer(int32_t keyCode);
    void HandleSpecialKeys(int32_t keyCode, int32_t keyAction);
    void InterruptTimers();
    int32_t GetKeyDownDurationFromXml(const std::string &businessId);
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
    void OnHandleTouchEvent(const std::shared_ptr<PointerEvent>& touchEvent);
    void StartTwoFingerGesture();
    void StopTwoFingerGesture();

private:
    ShortcutKey lastMatchedKey_;
    ShortcutKey currentLaunchAbilityKey_;
    std::map<std::string, ShortcutKey> shortcutKeys_;
    std::vector<Sequence> sequences_;
    std::vector<Sequence> filterSequences_;
    std::vector<SequenceKey> keys_;
    std::vector<std::string> businessIds_;
    bool isParseConfig_ { false };
    std::map<int32_t, int32_t> specialKeys_;
    std::map<int32_t, std::list<int32_t>> specialTimers_;
    TwoFingerGesture twoFingerGesture_;
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_COMMAND_HANDLER_H