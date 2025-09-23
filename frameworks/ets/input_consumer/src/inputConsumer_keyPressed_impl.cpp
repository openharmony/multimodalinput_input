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

#include "inputConsumer_keyPressed_impl.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "inputConsumer_keyPressed_impl"

namespace OHOS {
namespace MMI {
using namespace ohos::multimodalInput::keyCode;

ohos::multimodalInput::keyEvent::KeyEvent TaiheInvalidKeyPressed()
{
    return {
        {
            0,
            0,
            0,
            0,
            0
        },
        ohos::multimodalInput::keyEvent::Action::key_t::CANCEL,
        {
            ohos::multimodalInput::keyCode::KeyCode::key_t::KEYCODE_UNKNOWN,
            0,
            0
        },
        0,
        ::taihe::array<ohos::multimodalInput::keyEvent::Key>(nullptr, 0),
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false
    };
}

int32_t EtsKeyActionToKeyAction(int32_t action)
{
    static const std::map<int32_t, int32_t> keyActionMap {
        { EtsKeyAction::ETS_KEY_ACTION_CANCEL, KeyEvent::KEY_ACTION_CANCEL },
        { EtsKeyAction::ETS_KEY_ACTION_DOWN, KeyEvent::KEY_ACTION_DOWN },
        { EtsKeyAction::ETS_KEY_ACTION_UP, KeyEvent::KEY_ACTION_UP },
    };
    if (auto iter = keyActionMap.find(action); iter != keyActionMap.cend()) {
        return iter->second;
    } else {
        return KeyEvent::KEY_ACTION_UNKNOWN;
    }
}

EtsKeyAction KeyActionEtsKeyAction(int32_t action)
{
    static const std::map<int32_t, EtsKeyAction> keyActionMap {
        { KeyEvent::KEY_ACTION_CANCEL, ETS_KEY_ACTION_CANCEL },
        { KeyEvent::KEY_ACTION_DOWN, ETS_KEY_ACTION_DOWN },
        { KeyEvent::KEY_ACTION_UP, ETS_KEY_ACTION_UP },
    };
    if (auto iter = keyActionMap.find(action); iter != keyActionMap.cend()) {
        return iter->second;
    } else {
        return ETS_KEY_ACTION_CANCEL;
    }
}

ohos::multimodalInput::keyEvent::Action ConverKeyAction(EtsKeyAction action)
{
    switch (action) {
        case ETS_KEY_ACTION_CANCEL:
            return ohos::multimodalInput::keyEvent::Action::key_t::CANCEL;
        case ETS_KEY_ACTION_DOWN:
            return ohos::multimodalInput::keyEvent::Action::key_t::DOWN;
        case ETS_KEY_ACTION_UP:
            return ohos::multimodalInput::keyEvent::Action::key_t::UP;
    }
}

ohos::multimodalInput::keyEvent::Key KeyItemEtsKey(const KeyEvent::KeyItem &keyItem)
{
    return {
        ConvertEtsKeyCode(keyItem.GetKeyCode()),
        keyItem.GetDownTime(),
        keyItem.GetDeviceId()
    };
}

ohos::multimodalInput::keyEvent::KeyEvent ConverTaiheKeyPressed(std::shared_ptr<KeyEvent> keyEvent)
{
    if (keyEvent == nullptr) {
        MMI_HILOGE("keyEvent is nullptr");
        return TaiheInvalidKeyPressed();
    }
    auto keyItem = keyEvent->GetKeyItem();
    if (!keyItem) {
        MMI_HILOGE("No key item(No:%{public}d,KC:%{private}d)", keyEvent->GetId(), keyEvent->GetKeyCode());
        return TaiheInvalidKeyPressed();
    }
    std::vector<ohos::multimodalInput::keyEvent::Key> etsKey;
    ohos::multimodalInput::keyEvent::Key keycode = {
        ohos::multimodalInput::keyCode::KeyCode::key_t::KEYCODE_UNKNOWN,
        0,
        0
    };
    auto keyItems = keyEvent->GetKeyItems();
    for (const auto &keyItem : keyItems) {
        keycode = KeyItemEtsKey(keyItem);
        etsKey.push_back(keycode);
    }
    return {
        {
            keyEvent->GetId(),
            keyEvent->GetDeviceId(),
            keyEvent->GetActionTime(),
            keyEvent->GetTargetDisplayId(),
            keyEvent->GetTargetWindowId()
        },
        ConverKeyAction(KeyActionEtsKeyAction(keyEvent->GetKeyAction())),
        keycode,
        keyItem->GetUnicode(),
        ::taihe::array<ohos::multimodalInput::keyEvent::Key>(etsKey),
        keyEvent->GetKeyItem(KeyEvent::KEYCODE_CTRL_RIGHT).has_value(),
        keyEvent->GetKeyItem(KeyEvent::KEYCODE_ALT_RIGHT).has_value(),
        keyEvent->GetKeyItem(KeyEvent::KEYCODE_SHIFT_RIGHT).has_value(),
        keyEvent->GetKeyItem(KeyEvent::KEYCODE_META_RIGHT).has_value(),
        keyEvent->GetKeyItem(KeyEvent::KEYCODE_FN).has_value(),
        keyEvent->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY),
        keyEvent->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY),
        keyEvent->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY)
    };
}
} // namespace MMI
} // namespace OHOS