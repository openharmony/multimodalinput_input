/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef HARDWARE_CURSOR_POINTER_MANAGER_MOCK_H
#define HARDWARE_CURSOR_POINTER_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>
#include <parameters.h>

#include "singleton.h"
#include "buffer_handle.h"

namespace OHOS {
namespace MMI {
class IHardwareCursorPointerManager {
public:
    IHardwareCursorPointerManager() = default;
    virtual ~IHardwareCursorPointerManager() = default;

    virtual void SetHdiServiceState(bool hdiServiceState);
    virtual bool IsSupported();
    virtual int32_t SetPosition(uint32_t devId, int32_t x, int32_t y, BufferHandle* buffer);
    virtual int32_t EnableStats(bool enable);
    virtual int32_t GetCursorStats(uint32_t &frameCount, uint32_t &vsyncCount);
};

class HardwareCursorPointerManager final : public IHardwareCursorPointerManager {
public:
    HardwareCursorPointerManager() = default;
    ~HardwareCursorPointerManager() override = default;

    MOCK_METHOD(void, SetHdiServiceState, (bool));
    MOCK_METHOD(bool, IsSupported, ());
    MOCK_METHOD(int32_t, SetPosition, (uint32_t, int32_t, int32_t, BufferHandle*));
    MOCK_METHOD(int32_t, EnableStats, (bool));
    MOCK_METHOD(int32_t, GetCursorStats, (uint32_t&, uint32_t&));

    static std::shared_ptr<HardwareCursorPointerManager> GetInstance();
    static void ReleaseInstance();

private:
    static std::shared_ptr<HardwareCursorPointerManager> instance_;
};
} // namespace MMI
} // namespace OHOS
#endif // HARDWARE_CURSOR_POINTER_MANAGER_MOCK_H