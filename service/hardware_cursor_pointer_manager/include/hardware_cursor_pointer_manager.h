/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef HARDWARE_CURSOR_POINTER_MANAGER_H
#define HARDWARE_CURSOR_POINTER_MANAGER_H

#include <mutex>
#include <parameters.h>

#include "singleton.h"
#include "v1_2/include/idisplay_composer_interface.h"

namespace OHOS {
namespace MMI {
class HardwareCursorPointerManager {
public:
    HardwareCursorPointerManager() = default;
    ~HardwareCursorPointerManager() = default;
    void SetTargetDevice(uint32_t devId);
    void SetHdiServiceState(bool hdiServiceState);
    bool IsSupported();
    int32_t SetPosition(uint32_t devId, int32_t x, int32_t y, BufferHandle* buffer);
    int32_t EnableStats(bool enable);
    int32_t GetCursorStats(uint32_t &frameCount, uint32_t &vsyncCount);
private:
    sptr<OHOS::HDI::Display::Composer::V1_2::IDisplayComposerInterface> GetPowerInterface();
    bool isEnableState_ { false };
    bool isEnable_ { false };
    bool isDeviceChange_ { false };
    uint32_t devId_ { 0 };
    sptr<OHOS::HDI::Display::Composer::V1_2::IDisplayComposerInterface> powerInterface_ = nullptr;
    std::mutex mtx_;
};
} // namespace MMI
} // namespace OHOS
#endif // HARDWARE_CURSOR_POINTER_MANAGER_H
