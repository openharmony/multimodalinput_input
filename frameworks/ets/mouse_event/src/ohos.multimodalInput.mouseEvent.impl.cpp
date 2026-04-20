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

#include "ohos.multimodalInput.mouseEvent.impl.h"
 
#include "pointer_event.h"

#include <stdexcept>

#include "taihe/runtime.hpp"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ohos.multimodalInput.mouseEvent.impl"

using namespace taihe;
using namespace ohos::multimodalInput::mouseEvent;

using namespace OHOS::MMI;
namespace OHOS {
namespace MMI {
const static std::map<::ohos::multimodalInput::mouseEvent::Button, int32_t> MOUSE_BUTTON_TRANSFORMATION = {
    { ::ohos::multimodalInput::mouseEvent::Button::key_t::LEFT, PointerEvent::MOUSE_BUTTON_LEFT},
    { ::ohos::multimodalInput::mouseEvent::Button::key_t::MIDDLE, PointerEvent::MOUSE_BUTTON_MIDDLE},
    { ::ohos::multimodalInput::mouseEvent::Button::key_t::RIGHT, PointerEvent::MOUSE_BUTTON_RIGHT},
    { ::ohos::multimodalInput::mouseEvent::Button::key_t::SIDE, PointerEvent::MOUSE_BUTTON_SIDE},
    { ::ohos::multimodalInput::mouseEvent::Button::key_t::EXTRA, PointerEvent::MOUSE_BUTTON_EXTRA},
    { ::ohos::multimodalInput::mouseEvent::Button::key_t::FORWARD, PointerEvent::MOUSE_BUTTON_FORWARD},
    { ::ohos::multimodalInput::mouseEvent::Button::key_t::BACK, PointerEvent::MOUSE_BUTTON_BACK},
    { ::ohos::multimodalInput::mouseEvent::Button::key_t::TASK, PointerEvent::MOUSE_BUTTON_TASK}
};
 
int32_t TaiheMouseButonConverter::ConvertEts2Native(::ohos::multimodalInput::mouseEvent::Button button)
{
    if (MOUSE_BUTTON_TRANSFORMATION.find(button) !=
        MOUSE_BUTTON_TRANSFORMATION.end()) {
        return MOUSE_BUTTON_TRANSFORMATION.at(button);
    }
    return PointerEvent::BUTTON_NONE;
}
} //MMI
} // OHOS

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
// NOLINTEND