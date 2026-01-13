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

#ifndef KEY_COMMAND_TYPES_H
#define KEY_COMMAND_TYPES_H

#include <map>
#include <memory>
#include <vector>
#include "i_input_event_handler.h"

namespace OHOS {
namespace MMI {
enum KeyCommandType : int32_t {
    TYPE_SHORTKEY = 0,
    TYPE_SEQUENCE = 1,
    TYPE_FINGERSCENE = 2,
    TYPE_REPEAT_KEY = 3,
    TYPE_MULTI_FINGERS = 4,
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
#ifdef SHORTCUT_KEY_MANAGER_ENABLED
    int32_t shortcutId { -1 };
#endif // SHORTCUT_KEY_MANAGER_ENABLED
    Ability ability;
    void Print() const;
    std::string key;
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
    int64_t startTime = 0;
    int32_t windowId = -1;
    int32_t windowPid = -1;
    bool longPressFlag = false;
    std::shared_ptr<PointerEvent> touchEvent = nullptr;
    Ability ability;
    struct {
        int32_t id { 0 };
        int32_t x { 0 };
        int32_t y { 0 };
        int64_t downTime { 0 };
    } touches[MAX_TOUCH_NUM];
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
    Ability preNotifyAbility;
};

struct MultiFingersTap {
    Ability ability;
};
}  // namespace MMI
}  // namespace OHOS
#endif // KEY_COMMAND_TYPES_H
