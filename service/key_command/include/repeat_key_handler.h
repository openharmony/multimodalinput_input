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

#ifndef REPEAT_KEY_HANDLER_H
#define REPEAT_KEY_HANDLER_H

#include "i_key_command_service.h"
#include "key_command_context.h"
#include "key_command_types.h"

namespace OHOS {
namespace MMI {
class RepeatKeyHandler {
public:
    explicit RepeatKeyHandler(KeyCommandContext& context, IKeyCommandService& service)
        : context_(context), service_(service) {}
    ~RepeatKeyHandler() = default;
    bool HandleRepeatKeys(const std::shared_ptr<KeyEvent> keyEvent);

private:
    bool HandleRepeatKey(const RepeatKey& item, const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleRepeatKeyCount(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent);
    bool HandleRepeatKeyAbility(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent, bool isMaxTimes);
    void HandleRepeatKeyOwnCount(const RepeatKey &item);
    bool HandleKeyUpCancel(const RepeatKey &item, const std::shared_ptr<KeyEvent> keyEvent);
    bool CheckSpecialRepeatKey(RepeatKey& item, const std::shared_ptr<KeyEvent> keyEvent);
    void SendKeyEvent();
    bool IsMusicActivate();
    void PreNotify(const RepeatKey &item);
    std::shared_ptr<KeyEvent> CreateKeyEvent(int32_t keyCode, int32_t keyAction, bool isPressed);
    bool IsCallScene();

private:
    std::map<std::string, int32_t> repeatKeyTimerIds_;
    int32_t repeatTimerId_ { -1 };
    int64_t downActionTime_ { 0 };
    int64_t lastDownActionTime_ { 0 };
    int64_t upActionTime_ { 0 };
    bool isKeyCancel_ { false };

private:
    KeyCommandContext& context_;
    IKeyCommandService& service_;
};
} // namespace MMI
} // namespace OHOS
#endif // REPEAT_KEY_HANDLER_H

