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

#ifndef MMI_KEY_EVENT_VALUE_TRANSFORMATION_MOCK_H
#define MMI_KEY_EVENT_VALUE_TRANSFORMATION_MOCK_H
#include <vector>
#include <gmock/gmock.h>
#include "key_event.h"

namespace OHOS {
namespace MMI {
struct KeyEventValueTransformation {
    std::string keyEvent;
    int32_t nativeKeyValue { 0 };
    int32_t sysKeyValue { 0 };
    int32_t sysKeyEvent { 0 };
};

KeyEventValueTransformation TransferKeyValue(int32_t keyValueOfInput);
int32_t InputTransformationKeyValue(int32_t keyCode);
int32_t KeyItemsTransKeyIntention(const std::vector<KeyEvent::KeyItem> &items);

class IKeyEventValueTransformer {
public:
    IKeyEventValueTransformer();
    virtual ~IKeyEventValueTransformer() = default;

    virtual KeyEventValueTransformation TransferKeyValue(int32_t keyValueOfInput) = 0;
    virtual int32_t InputTransformationKeyValue(int32_t keyCode) = 0;
    virtual int32_t KeyItemsTransKeyIntention(const std::vector<KeyEvent::KeyItem> &items) = 0;
};

class KeyEventValueTransformer : public IKeyEventValueTransformer {
public:
    KeyEventValueTransformer() = default;
    virtual ~KeyEventValueTransformer() = default;

    MOCK_METHOD(KeyEventValueTransformation, TransferKeyValue, (int32_t));
    MOCK_METHOD(int32_t, InputTransformationKeyValue, (int32_t));
    MOCK_METHOD(int32_t, KeyItemsTransKeyIntention, (const std::vector<KeyEvent::KeyItem> &));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_KEY_EVENT_VALUE_TRANSFORMATION_MOCK_H