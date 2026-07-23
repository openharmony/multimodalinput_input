/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MMI_KEY_COMMAND_HANDLER_UTIL_MOCK_H
#define MMI_KEY_COMMAND_HANDLER_UTIL_MOCK_H

#include <cstdint>
#include <gmock/gmock.h>

namespace OHOS {
namespace MMI {
enum SpecialType {
    SPECIAL_ALL,
    SUBSCRIBER_BEFORE_DELAY,
    KEY_DOWN_ACTION
};

class IKeyCommandHandlerUtil {
public:
    IKeyCommandHandlerUtil();
    virtual ~IKeyCommandHandlerUtil() = default;

    virtual bool IsSpecialType(int32_t keyCode, SpecialType type) = 0;
};

class KeyCommandHandlerUtil : public IKeyCommandHandlerUtil {
public:
    KeyCommandHandlerUtil() = default;
    ~KeyCommandHandlerUtil() override = default;

    MOCK_METHOD(bool, IsSpecialType, (int32_t, SpecialType));
};

bool IsSpecialType(int32_t keyCode, SpecialType type);
} // namespace MMI
} // namespace OHOS
#endif // MMI_KEY_COMMAND_HANDLER_UTIL_MOCK_H
