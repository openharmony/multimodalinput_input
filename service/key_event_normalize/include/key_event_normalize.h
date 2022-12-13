/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

#include "input_windows_manager.h"
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

private:
    std::shared_ptr<KeyEvent> keyEvent_ { nullptr };
};
#define KeyEventHdr ::OHOS::DelayedSingleton<KeyEventNormalize>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // KEY_EVENT_NORMALIZE_H