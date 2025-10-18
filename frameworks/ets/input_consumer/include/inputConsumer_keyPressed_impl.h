/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INPUT_CONSUMER_KEY_PRESSED_IMPL_H
#define INPUT_CONSUMER_KEY_PRESSED_IMPL_H

#include <stdexcept>

#include "define_multimodal.h"
#include "input_manager.h"
#include "ohos.multimodalInput.inputConsumer.proj.hpp"
#include "ohos.multimodalInput.inputConsumer.impl.hpp"
#include "ohos.multimodalInput.keyCode.impl.h"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace MMI {
namespace inputConsumer = ohos::multimodalInput::inputConsumer;
namespace keyEvent = ohos::multimodalInput::keyEvent;
namespace keyCode = ohos::multimodalInput::keyCode;

enum EtsKeyAction {
    ETS_KEY_ACTION_CANCEL,
    ETS_KEY_ACTION_DOWN,
    ETS_KEY_ACTION_UP,
};

static const std::set<int32_t> allowedKeys_ {
    KeyEvent::KEYCODE_VOLUME_DOWN,
    KeyEvent::KEYCODE_VOLUME_UP,
};

int32_t EtsKeyActionToKeyAction(int32_t action);
EtsKeyAction KeyActionEtsKeyAction(int32_t action);
keyEvent::Key KeyItemEtsKey(const KeyEvent::KeyItem &keyItem);
keyEvent::Action ConvertKeyAction(EtsKeyAction action);
keyEvent::KeyEvent ConvertTaiheKeyPressed(std::shared_ptr<KeyEvent> keyEvent);
} // namespace MMI
} // namespace OHOS
#endif // INPUT_CONSUMER_KEY_PRESSED_IMPL_H