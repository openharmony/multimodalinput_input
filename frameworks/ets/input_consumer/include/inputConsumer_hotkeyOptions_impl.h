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

#ifndef INPUT_CONSUMER_HOT_KEY_OPTIONS_IMPL_H
#define INPUT_CONSUMER_HOT_KEY_OPTIONS_IMPL_H

#include <stdexcept>

#include "define_multimodal.h"
#include "input_manager.h"
#include "ohos.multimodalInput.inputConsumer.proj.hpp"
#include "ohos.multimodalInput.inputConsumer.impl.hpp"
#include "taihe/runtime.hpp"

namespace OHOS {
namespace MMI {
namespace inputConsumer = ohos::multimodalInput::inputConsumer;

static const std::vector<int32_t> pressKeyCodes = {
    KeyEvent::KEYCODE_ALT_LEFT,
    KeyEvent::KEYCODE_ALT_RIGHT,
    KeyEvent::KEYCODE_SHIFT_LEFT,
    KeyEvent::KEYCODE_SHIFT_RIGHT,
    KeyEvent::KEYCODE_CTRL_LEFT,
    KeyEvent::KEYCODE_CTRL_RIGHT
};

static const std::vector<int32_t> finalKeyCodes = {
    KeyEvent::KEYCODE_ALT_LEFT,
    KeyEvent::KEYCODE_ALT_RIGHT,
    KeyEvent::KEYCODE_SHIFT_LEFT,
    KeyEvent::KEYCODE_SHIFT_RIGHT,
    KeyEvent::KEYCODE_CTRL_LEFT,
    KeyEvent::KEYCODE_CTRL_RIGHT,
    KeyEvent::KEYCODE_META_LEFT,
    KeyEvent::KEYCODE_META_RIGHT
};

inputConsumer::HotkeyOptions ConvertTaiheHotkeyOptions(std::shared_ptr<KeyOption> keyOption);
} // namespace MMI
} // namespace OHOS
#endif // INPUT_CONSUMER_HOT_KEY_OPTIONS_IMPL_H