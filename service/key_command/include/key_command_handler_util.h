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

#ifndef KEY_COMMAND_HANDLER_UTIL_H
#define KEY_COMMAND_HANDLER_UTIL_H

#include "cJSON.h"
#include "config_policy_utils.h"
#include "file_ex.h"
#include "system_ability_definition.h"

#include "ability_manager_client.h"
#include "bytrace_adapter.h"
#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "display_event_monitor.h"
#include "error_multimodal.h"
#include "input_event_data_transformation.h"
#include "input_event_handler.h"
#include "i_preference_manager.h"
#include "key_command_handler.h"
#include "mmi_log.h"
#include "nap_process.h"
#include "net_packet.h"
#include "proto.h"
#include "setting_datashare.h"
#include "timer_manager.h"
#include "util_ex.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCommandHandlerUtil"

namespace OHOS {
namespace MMI {
constexpr int32_t MAX_PREKEYS_NUM = 4;
constexpr int32_t MAX_SEQUENCEKEYS_NUM = 10;
constexpr int64_t MAX_DELAY_TIME = 1000000;
constexpr int64_t SECONDS_SYSTEM = 1000;
constexpr int32_t SPECIAL_KEY_DOWN_DELAY = 150;
constexpr int32_t MAX_SHORT_KEY_DOWN_DURATION = 4000;
constexpr int32_t MIN_SHORT_KEY_DOWN_DURATION = 0;
constexpr int32_t TOUCH_MAX_THRESHOLD = 20;
constexpr int32_t TWO_FINGERS_DISTANCE_LIMIT = 16;
constexpr int32_t TWO_FINGERS_TIME_LIMIT = 150000;
constexpr int32_t TOUCH_LIFT_LIMIT = 24;
constexpr int32_t TOUCH_RIGHT_LIMIT = 24;
constexpr int32_t TOUCH_TOP_LIMIT = 80;
constexpr int32_t TOUCH_BOTTOM_LIMIT = 41;
constexpr int32_t PARAMETER_ERROR = 401;
constexpr int32_t KNUCKLE_KNOCKS = 1;
constexpr size_t SINGLE_KNUCKLE_SIZE = 1;
constexpr size_t DOUBLE_KNUCKLE_SIZE = 2;
constexpr int32_t MAX_TIME_FOR_ADJUST_CONFIG = 5;
constexpr int32_t POW_SQUARE = 2;
constexpr int64_t DOUBLE_CLICK_INTERVAL_TIME_DEFAULT = 250000;
constexpr int64_t DOUBLE_CLICK_INTERVAL_TIME_SLOW = 450000;
constexpr float DOUBLE_CLICK_DISTANCE_DEFAULT_CONFIG = 64.0f;
constexpr float DOUBLE_CLICK_DISTANCE_LONG_CONFIG = 96.0f;
constexpr float VPR_CONFIG = 3.25f;
constexpr int32_t REMOVE_OBSERVER = -2;
constexpr int32_t ACTIVE_EVENT = 2;
constexpr int32_t LONG_ABILITY_START_DELAY = 2000;
constexpr int32_t WINDOW_INPUT_METHOD_TYPE = 2105;
const std::string EXTENSION_ABILITY = "extensionAbility";
const std::string SINGLE_KNUCKLE_ABILITY = "SingleKnuckleDoubleClickGesture";
const std::string DOUBLE_KNUCKLE_ABILITY = "DoubleKnuckleDoubleClickGesture";
const std::string TOUCHPAD_TRIP_TAP_ABILITY = "ThreeFingersTap";
const std::string SETTING_KNUCKLE_SWITCH = "settings.game.forbid_finger_knuckle";

enum SpecialType {
    SPECIAL_ALL = 0,
    SUBSCRIBER_BEFORE_DELAY = 1,
    KEY_DOWN_ACTION = 2
};
const std::map<int32_t, SpecialType> SPECIAL_KEYS = {
    { KeyEvent::KEYCODE_POWER, SpecialType::KEY_DOWN_ACTION }
};
struct JsonParser {
    JsonParser() = default;
    ~JsonParser()
    {
        if (json_ != nullptr) {
            cJSON_Delete(json_);
        }
    }
    operator cJSON *()
    {
        return json_;
    }
    cJSON *json_ { nullptr };
};

bool IsSpecialType(int32_t keyCode, SpecialType type);
bool GetBusinessId(const cJSON* jsonData, std::string &businessIdValue, std::vector<std::string> &businessIds);
bool GetPreKeys(const cJSON* jsonData, ShortcutKey &shortcutKey);
bool GetTrigger(const cJSON* jsonData, int32_t &triggerType);
bool GetKeyDownDuration(const cJSON* jsonData, int32_t &keyDownDurationInt);
bool GetKeyFinalKey(const cJSON* jsonData, int32_t &finalKeyInt);
void GetKeyVal(const cJSON* json, const std::string &key, std::string &value);
bool GetEntities(const cJSON* jsonAbility, Ability &ability);
bool GetParams(const cJSON* jsonAbility, Ability &ability);
bool PackageAbility(const cJSON* jsonAbility, Ability &ability);
bool ConvertToShortcutKey(const cJSON* jsonData, ShortcutKey &shortcutKey, std::vector<std::string> &businessIds);
bool GetKeyCode(const cJSON* jsonData, int32_t &keyCodeInt);
bool GetKeyAction(const cJSON* jsonData, int32_t &keyActionInt);
bool GetDelay(const cJSON* jsonData, int64_t &delayInt);
bool GetRepeatTimes(const cJSON* jsonData, int32_t &repeatTimesInt);
bool GetAbilityStartDelay(const cJSON* jsonData, int64_t &abilityStartDelayInt);
bool PackageSequenceKey(const cJSON* sequenceKeysJson, SequenceKey &sequenceKey);
bool GetSequenceKeys(const cJSON* jsonData, Sequence &sequence);
bool IsSequenceKeysValid(const Sequence &sequence);
bool ConvertToKeySequence(const cJSON* jsonData, Sequence &sequence);
bool ConvertToExcludeKey(const cJSON* jsonData, ExcludeKey &exKey);
bool ConvertToKeyRepeat(const cJSON* jsonData, RepeatKey &repeatKey);
std::string GenerateKey(const ShortcutKey& key);
bool ParseShortcutKeys(const JsonParser& parser, std::map<std::string, ShortcutKey>& shortcutKeyMap,
    std::vector<std::string>& businessIds);
bool ParseSequences(const JsonParser& parser, std::vector<Sequence>& sequenceVec);
bool ParseExcludeKeys(const JsonParser& parser, std::vector<ExcludeKey>& excludeKeyVec);
bool ParseRepeatKeys(const JsonParser& parser, std::vector<RepeatKey>& repeatKeyVec);
bool ParseTwoFingerGesture(const JsonParser& parser, TwoFingerGesture& gesture);
bool IsPackageKnuckleGesture(const cJSON* jsonData, const std::string knuckleGesture, Ability &launchAbility);
bool IsParseKnuckleGesture(const JsonParser &parser, const std::string ability, KnuckleGesture &knuckleGesture);
float AbsDiff(KnuckleGesture knuckleGesture, const std::shared_ptr<PointerEvent> pointerEvent);
bool IsEqual(float f1, float f2);
bool ParseMultiFingersTap(const JsonParser &parser, const std::string ability, MultiFingersTap &mulFingersTap);
} // namespace MMI
} // namespace OHOS
#endif // KEY_COMMAND_HANDLER_UTIL_H