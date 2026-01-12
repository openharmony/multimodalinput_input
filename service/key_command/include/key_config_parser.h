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

#ifndef KEY_CONFIG_PARSER_H
#define KEY_CONFIG_PARSER_H

#include "i_key_command_service.h"
#include "key_command_context.h"
#include "key_command_types.h"
#include "json_parser.h"

namespace OHOS {
namespace MMI {
class KeyConfigParser {
public:
    explicit KeyConfigParser(KeyCommandContext& context, IKeyCommandService& service)
        : context_(context), service_(service) {}
    ~KeyConfigParser() = default;

    bool ParseConfig();
    bool ParseJson(const std::string &configFile);
    bool ParseExcludeConfig();
    bool ParseExcludeJson(const std::string &configFile);
    bool ParseShortcutKeys(const JsonParser& parser, std::map<std::string, ShortcutKey>& shortcutKeyMap,
        std::vector<std::string>& businessIds);
    bool ParseSequences(const JsonParser& parser, std::vector<Sequence>& sequenceVec);
    bool ParseRepeatKeys(const JsonParser& parser, std::vector<RepeatKey>& repeatKeyVec,
        std::map<int32_t, int32_t>& repeatKeyMaxTimes);
    bool ParseTwoFingerGesture(const JsonParser& parser, TwoFingerGesture& gesture);
    bool ParseExcludeKeys(const JsonParser& parser, std::vector<ExcludeKey>& excludeKeyVec);
    bool ParseMultiFingersTap(const JsonParser &parser, const std::string ability, MultiFingersTap &mulFingersTap);
    void Print();
    void PrintSeq();
    void PrintExcludeKeys();

private:
    bool ConvertToExcludeKey(const cJSON* jsonData, ExcludeKey &exKey);
    bool ConvertToShortcutKey(const cJSON* jsonData, ShortcutKey &shortcutKey, std::vector<std::string> &businessIds);
    bool ConvertToKeySequence(const cJSON* jsonData, Sequence &sequence);
    bool ConvertToKeyRepeat(const cJSON* jsonData, RepeatKey &repeatKey);
    bool GetBusinessId(const cJSON* jsonData, std::string &businessIdValue, std::vector<std::string> &businessIds);
    bool GetPreKeys(const cJSON* jsonData, ShortcutKey &shortcutKey);
    bool GetKeyFinalKey(const cJSON* jsonData, int32_t &finalKeyInt);
    bool GetTrigger(const cJSON* jsonData, int32_t &triggerType);
    bool GetKeyDownDuration(const cJSON* jsonData, int32_t &keyDownDurationInt);

    bool PackageSequenceKey(const cJSON* sequenceKeysJson, SequenceKey &sequenceKey);
    std::string GenerateKey(const ShortcutKey& key);
    bool GetSequenceKeys(const cJSON* jsonData, Sequence &sequence);
    bool IsSequenceKeysValid(const Sequence &sequence);
    bool GetKeyCode(const cJSON* jsonData, int32_t &keyCodeInt);
    bool GetKeyAction(const cJSON* jsonData, int32_t &keyActionInt);
    bool GetDelay(const cJSON* jsonData, int64_t &delayInt);
    bool GetRepeatTimes(const cJSON* jsonData, int32_t &repeatTimesInt);
    bool GetRepeatKeyDelay(const cJSON* jsonData, int64_t &delayInt);
    int32_t RegisterSystemKey(const ShortcutKey &shortcutKey, std::function<void(std::shared_ptr<KeyEvent>)> callback);

    bool IsPackageKnuckleGesture(const cJSON* jsonData, const std::string knuckleGesture, Ability &launchAbility);
    bool PackageAbility(const cJSON* jsonAbility, Ability &ability);
    void GetKeyVal(const cJSON* json, const std::string &key, std::string &value);
    bool GetEntities(const cJSON* jsonAbility, Ability &ability);
    bool GetParams(const cJSON* jsonAbility, Ability &ability);

private:
    KeyCommandContext& context_;
    IKeyCommandService& service_;
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_CONFIG_PARSER_H

