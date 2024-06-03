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

#include "hardware_cursor_pointer_manager.h"

#include <thread>

#include "mmi_log.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_CURSOR
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "HardwareCursorPointerManager"

namespace OHOS {
namespace MMI {
void HardwareCursorPointerManager::SetTargetDevice(uint32_t devId)
{
    if (devId != devId_) {
        devId_ = devId;
        MMI_HILOGI("SetTargetDevice devId_ changed");
        isEnableState_ = false;
    }
}

bool HardwareCursorPointerManager::IsSupported()
{
    isEnableState_ = true;
    return true;
}

int32_t HardwareCursorPointerManager::SetPosition(int32_t x, int32_t y)
{
    MMI_HILOGD("SetPosition, x:%{public}d, y:%{public}d", x, y);
    return RET_OK;
}

int32_t HardwareCursorPointerManager::EnableStats(bool enable)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("EnableStats, enable:%{public}d", enable);
    return RET_OK;
}

int32_t HardwareCursorPointerManager::GetCursorStats(uint32_t &frameCount, uint32_t &vsyncCount)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Get hardware cursor stats, frameCount:%{public}d, vsyncCount:%{public}d", frameCount, vsyncCount);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS
