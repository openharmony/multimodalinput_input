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

#ifndef MMI_KEY_EVENT_NORMALIZE_MOCK_H
#define MMI_KEY_EVENT_NORMALIZE_MOCK_H
#include <gmock/gmock.h>
#include "key_event.h"

namespace OHOS {
namespace MMI {
class IKeyEventNormalize {
public:
    IKeyEventNormalize() = default;
    virtual ~IKeyEventNormalize() = default;

    virtual std::shared_ptr<KeyEvent> GetKeyEvent() = 0;
    virtual int32_t SetShieldStatus(int32_t shieldMode, bool isShield) = 0;
    virtual int32_t GetShieldStatus(int32_t shieldMode, bool &isShield) = 0;
};

class KeyEventNormalizeMock : public IKeyEventNormalize {
public:
    KeyEventNormalizeMock() = default;
    virtual ~KeyEventNormalizeMock() override = default;

    MOCK_METHOD(std::shared_ptr<KeyEvent>, GetKeyEvent, ());
    MOCK_METHOD(int32_t, SetShieldStatus, (int32_t, bool));
    MOCK_METHOD(int32_t, GetShieldStatus, (int32_t, bool&));

    static std::shared_ptr<KeyEventNormalizeMock> GetInstance();
    static void ReleaseInstance();

private:
    static std::shared_ptr<KeyEventNormalizeMock> instance_;
};

#define KeyEventHdr KeyEventNormalizeMock::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_KEY_EVENT_NORMALIZE_MOCK_H