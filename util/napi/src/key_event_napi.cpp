/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "key_event_napi.h"

#include "util_napi.h"
#include "util_napi_value.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventNapi"

namespace OHOS {
namespace MMI {
napi_status KeyEventNapi::CreateKeyEvent(napi_env env, const std::shared_ptr<KeyEvent> &in, napi_value &out)
{
    auto status = SetNameProperty(env, out, "action", in->GetKeyAction() - KeyEvent::KEY_ACTION_CANCEL);
    CHKRR(status, "set action property", status);

    CHECK_RETURN(in->GetKeyItem(), "get key item", status);
    auto keyItem = in->GetKeyItem();
    status = SetNameProperty(env, out, "key", keyItem);
    CHKRR(status, "set key property", status);

    status = SetNameProperty(env, out, "unicodeChar", in->GetKeyItem()->GetUnicode());
    CHKRR(status, "set unicodeChar property", status);

    auto keyItems = in->GetKeyItems();
    status = SetNameProperty(env, out, "keys", keyItems);
    CHKRR(status, "set keys property", status);

    status = WriteKeyStatusToJs(env, in->GetPressedKeys(), out);
    CHKRR(status, "set pressed key property", status);

    status = WriteFunctionKeyStatusToJs(env, in, out);
    CHKRR(status, "set function key property", status);

    return napi_ok;
}

napi_status KeyEventNapi::GetKeyEvent(napi_env env, napi_value in, std::shared_ptr<KeyEvent> &out)
{
    napi_valuetype valueType = napi_undefined;
    auto status = napi_typeof(env, in, &valueType);
    CHECK_RETURN((status == napi_ok) && (valueType == napi_object), "object type invalid", status);

    KeyEvent::KeyItem item = GetNamePropertyKeyItem(env, in, "key");
    out->SetKeyCode(item.GetKeyCode());

    uint32_t unicode = GetNamePropertyUint32(env, in, "unicodeChar");
    out->GetKeyItem()->SetUnicode(unicode);

    int32_t keyAction = GetNamePropertyInt32(env, in, "action");
    out->SetKeyAction(keyAction + KeyEvent::KEY_ACTION_CANCEL);

    std::vector<KeyEvent::KeyItem> keyItems = GetNamePropertyKeyItems(env, in, "keys");
    for (const auto &keyItem : keyItems) {
        out->AddKeyItem(keyItem);
    }

    bool lock = GetNamePropertyBool(env, in, "capsLock");
    out->SetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY, lock);
    lock = GetNamePropertyBool(env, in, "numLock");
    out->SetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY, lock);
    lock = GetNamePropertyBool(env, in, "scrollLock");
    out->SetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY, lock);

    return napi_ok;
}

napi_status KeyEventNapi::CreateKeyItem(napi_env env, const std::optional<KeyEvent::KeyItem> in, napi_value &out)
{
    auto status = SetNameProperty(env, out, "code", in->GetKeyCode());
    CHKRR(status, "set code property", status);

    status = SetNameProperty(env, out, "pressedTime", in->GetDownTime());
    CHKRR(status, "set pressedTime property", status);

    status = SetNameProperty(env, out, "deviceId", in->GetDeviceId());
    CHKRR(status, "set deviceId property", status);

    return napi_ok;
}

napi_status KeyEventNapi::GetKeyItem(napi_env env, napi_value in, KeyEvent::KeyItem &out)
{
    int32_t keyCode = GetNamePropertyInt32(env, in, "code");
    out.SetKeyCode(keyCode);
    int64_t downTime = GetNamePropertyInt64(env, in, "pressedTime");
    out.SetDownTime(downTime);
    int32_t deviceId = GetNamePropertyInt32(env, in, "deviceId");
    out.SetDeviceId(deviceId);
    return napi_ok;
}

napi_status KeyEventNapi::WriteKeyStatusToJs(napi_env env, const std::vector<int32_t> &pressedKeys, napi_value &out)
{
    bool isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_LEFT)
                    || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_CTRL_RIGHT);
    auto status = SetNameProperty(env, out, "ctrlKey", isExists);
    CHKRR(status, "set ctrlKey property", status);

    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_LEFT)
               || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_ALT_RIGHT);
    status = SetNameProperty(env, out, "altKey", isExists);
    CHKRR(status, "set altKey property", status);

    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_LEFT)
               || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_SHIFT_RIGHT);
    status = SetNameProperty(env, out, "shiftKey", isExists);
    CHKRR(status, "set shiftKey property", status);

    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_LEFT)
               || HasKeyCode(pressedKeys, KeyEvent::KEYCODE_META_RIGHT);
    status = SetNameProperty(env, out, "logoKey", isExists);
    CHKRR(status, "set logoKey property", status);

    isExists = HasKeyCode(pressedKeys, KeyEvent::KEYCODE_FN);
    status = SetNameProperty(env, out, "fnKey", isExists);
    CHKRR(status, "set fnKey property", status);

    return napi_ok;
}

napi_status KeyEventNapi::WriteFunctionKeyStatusToJs(napi_env env, const std::shared_ptr<KeyEvent> &in, napi_value &out)
{
    auto status = SetNameProperty(env, out, "capsLock", in->GetFunctionKey(KeyEvent::CAPS_LOCK_FUNCTION_KEY));
    CHKRR(status, "set capsLock property", status);

    status = SetNameProperty(env, out, "numLock", in->GetFunctionKey(KeyEvent::NUM_LOCK_FUNCTION_KEY));
    CHKRR(status, "set numLock property", status);

    status = SetNameProperty(env, out, "scrollLock", in->GetFunctionKey(KeyEvent::SCROLL_LOCK_FUNCTION_KEY));
    CHKRR(status, "set scrollLock property", status);

    return napi_ok;
}

bool KeyEventNapi::HasKeyCode(const std::vector<int32_t> &pressedKeys, int32_t keyCode)
{
    return std::find(pressedKeys.begin(), pressedKeys.end(), keyCode) != pressedKeys.end();
}
} // namespace MMI
} // namespace OHOS