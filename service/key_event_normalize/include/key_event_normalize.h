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

#ifndef KEY_EVENT_NORMALIZE_H
#define KEY_EVENT_NORMALIZE_H

#include "singleton.h"

#include "i_input_windows_manager.h"
#include "key_event.h"
#include "util.h"

namespace OHOS {
namespace MMI {
class KeyEventNormalize final {
    DECLARE_DELAYED_SINGLETON(KeyEventNormalize);
public:
    DISALLOW_COPY_AND_MOVE(KeyEventNormalize);
    std::shared_ptr<KeyEvent> GetKeyEvent();
    int32_t Normalize(libinput_event *event, std::shared_ptr<KeyEvent> keyEvent);
    void ResetKeyEvent(struct libinput_device* device);
    int32_t SetShieldStatus(int32_t shieldMode, bool isShield);
    int32_t GetShieldStatus(int32_t shieldMode, bool &isShield);
    void SetCurrentShieldMode(int32_t shieldMode);
    int32_t GetCurrentShieldMode();
private:
    void HandleKeyAction(struct libinput_device* device, KeyEvent::KeyItem &item, std::shared_ptr<KeyEvent> keyEvent);

private:
    std::shared_ptr<KeyEvent> keyEvent_ { nullptr };
    std::map<int32_t, bool> shieldStatus_ {
        {SHIELD_MODE::FACTORY_MODE, false},
        {SHIELD_MODE::OOBE_MODE, false},
    };
    int32_t lastShieldMode_ { -1 };
};
#define KeyEventHdr ::OHOS::DelayedSingleton<KeyEventNormalize>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // KEY_EVENT_NORMALIZE_H