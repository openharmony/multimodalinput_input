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

#include "key_unicode_transformation.h"

namespace OHOS {
namespace MMI {
namespace {
IKeyUnicodeTransformation *g_Instance = nullptr;
} // namespace

IKeyUnicodeTransformation::IKeyUnicodeTransformation()
{
    g_Instance = this;
}

bool IsShiftPressed(std::shared_ptr<KeyEvent> keyEvent)
{
    return g_Instance->IsShiftPressed(keyEvent);
}

uint32_t KeyCodeToUnicode(int32_t keyCode, std::shared_ptr<KeyEvent> keyEvent)
{
    return g_Instance->KeyCodeToUnicode(keyCode, keyEvent);
}
} // namespace MMI
} // namespace OHOS