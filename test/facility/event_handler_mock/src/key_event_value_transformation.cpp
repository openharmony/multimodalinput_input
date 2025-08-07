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

#include "key_event_value_transformation.h"

namespace OHOS {
namespace MMI {
namespace {
IKeyEventValueTransformer *g_Instance = nullptr;
}

IKeyEventValueTransformer::IKeyEventValueTransformer()
{
    g_Instance = this;
}

KeyEventValueTransformation TransferKeyValue(int32_t keyValueOfInput)
{
    return g_Instance->TransferKeyValue(keyValueOfInput);
}

int32_t InputTransformationKeyValue(int32_t keyCode)
{
    return g_Instance->InputTransformationKeyValue(keyCode);
}

int32_t KeyItemsTransKeyIntention(const std::vector<KeyEvent::KeyItem> &items)
{
    return g_Instance->KeyItemsTransKeyIntention(items);
}
} // namespace MMI
} // namespace OHOS