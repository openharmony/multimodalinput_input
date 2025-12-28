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

#ifndef SEQUENCE_KEY_HANDLER_H
#define SEQUENCE_KEY_HANDLER_H

#include "i_key_command_service.h"
#include "key_command_context.h"
#include "key_command_types.h"

namespace OHOS {
namespace MMI {
class SequenceKeyHandler {
public:
    explicit SequenceKeyHandler(KeyCommandContext& context, IKeyCommandService& service)
        : context_(context), service_(service) {}
    ~SequenceKeyHandler() = default;
    bool HandleSequences(const std::shared_ptr<KeyEvent> keyEvent);

private:
    bool AddSequenceKey(const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleSequence(Sequence& sequence, bool &isLaunchAbility);
    bool HandleMatchedSequence(Sequence& sequence, bool &isLaunchAbility);
    bool HandleScreenLocked(Sequence& sequence, bool &isLaunchAbility);
    bool HandleNormalSequence(Sequence& sequence, bool &isLaunchAbility);
    bool IsRepeatKeyEvent(const SequenceKey &sequenceKey);
    bool IsActiveSequenceRepeating(std::shared_ptr<KeyEvent> keyEvent) const;
    void MarkActiveSequence(bool active);
    void ResetSequenceKeys();
    void InterruptTimers();
    void RemoveSubscribedTimer(int32_t keyCode);
    void LaunchSequenceAbility(const Sequence &sequence);

private:
    Sequence matchedSequence_;
    std::vector<Sequence> filterSequences_;
    std::vector<SequenceKey> keys_;
    bool sequenceOccurred_ { false };

private:
    KeyCommandContext& context_;
    IKeyCommandService& service_;
};
} // namespace MMI
} // namespace OHOS
#endif // SEQUENCE_KEY_HANDLER_H

