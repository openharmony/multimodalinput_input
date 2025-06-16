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
#ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
void HardwareCursorPointerManager::SetTargetDevice(uint32_t devId)
{
    if (static_cast<int32_t>(devId) < 0) {
        MMI_HILOGE("SetTargetDevice devId %{public}d is invalid", static_cast<int32_t>(devId));
        return;
    }
 
    if (devId != devId_) {
        devId_ = devId;
        MMI_HILOGI("SetTargetDevice devId_ changed");
        isEnableState_ = false;
        isDeviceChange_ = false;
    }
}

void HardwareCursorPointerManager::SetHdiServiceState(bool hdiServiceState)
{
    isEnable_ = hdiServiceState;
}

bool HardwareCursorPointerManager::IsSupported()
{
    if (isEnable_ && isEnableState_) {
        return true;
    }
    if (isEnable_ && isDeviceChange_ && (isEnableState_ == false)) {
        return false;
    }
    if (!isEnable_) {
        auto DisplayComposer = OHOS::HDI::Display::Composer::V1_2::IDisplayComposerInterface::Get(false);
        std::lock_guard<std::mutex> guard(mtx_);
        powerInterface_ = DisplayComposer;
        CHKPF(powerInterface_);
        isEnable_ = true;
    }
    auto powerInterface = GetPowerInterface();
    CHKPF(powerInterface);
    uint64_t value = 0;
    if (powerInterface->GetDisplayProperty(devId_,
        HDI::Display::Composer::V1_2::DISPLAY_CAPBILITY_HARDWARE_CURSOR, value)
        != HDI::Display::Composer::V1_2::DISPLAY_SUCCESS) {
        MMI_HILOGE("Get display property is error");
        isDeviceChange_ = true;
        return false;
    }
    if (value) {
        MMI_HILOGI("Get display property is support");
        isEnableState_ = true;
    }
    isDeviceChange_ = true;
    return isEnableState_;
}

int32_t HardwareCursorPointerManager::SetPosition(uint32_t devId, int32_t x, int32_t y, BufferHandle* buffer)
{
    CHKPR(buffer, RET_ERR);

    auto powerInterface = GetPowerInterface();
    CHKPR(powerInterface, RET_ERR);
    if (powerInterface->UpdateHardwareCursor(devId, x, y, buffer) != HDI::Display::Composer::V1_2::DISPLAY_SUCCESS) {
        MMI_HILOGE("UpdateHardwareCursor failed, attempting to reinitialize interface");
        {
            auto DisplayComposer = OHOS::HDI::Display::Composer::V1_2::IDisplayComposerInterface::Get(false);
            std::lock_guard<std::mutex> guard(mtx_);
            powerInterface_ = DisplayComposer;
        }
        powerInterface = GetPowerInterface();
        CHKPR(powerInterface, RET_ERR);
        if (powerInterface->UpdateHardwareCursor(devId, x, y, buffer) !=
            HDI::Display::Composer::V1_2::DISPLAY_SUCCESS) {
            MMI_HILOGE("UpdateHardwareCursor is error");
            return RET_ERR;
        }
    }
    MMI_HILOGD("SetPosition, devId:%{public}u, x:%{private}d, y:%{private}d", devId, x, y);
    return RET_OK;
}

int32_t HardwareCursorPointerManager::EnableStats(bool enable)
{
    CALL_DEBUG_ENTER;
    auto powerInterface = GetPowerInterface();
    CHKPR(powerInterface, RET_ERR);
    if (powerInterface->EnableHardwareCursorStats(devId_, enable) != HDI::Display::Composer::V1_2::DISPLAY_SUCCESS) {
        MMI_HILOGE("Enable hardware cursor stats is error");
        return RET_ERR;
    }
    MMI_HILOGD("EnableStats, enable:%{public}d", enable);
    return RET_OK;
}

int32_t HardwareCursorPointerManager::GetCursorStats(uint32_t &frameCount, uint32_t &vsyncCount)
{
    CALL_DEBUG_ENTER;
    auto powerInterface = GetPowerInterface();
    CHKPR(powerInterface, RET_ERR);
    if (powerInterface->GetHardwareCursorStats(devId_, frameCount, vsyncCount) !=
        HDI::Display::Composer::V1_2::DISPLAY_SUCCESS) {
        MMI_HILOGE("Get hardware cursor stats is error");
        return RET_ERR;
    }
    MMI_HILOGD("Get hardware cursor stats, frameCount:%{private}d, vsyncCount:%{private}d", frameCount, vsyncCount);
    return RET_OK;
}

sptr<OHOS::HDI::Display::Composer::V1_2::IDisplayComposerInterface> HardwareCursorPointerManager::GetPowerInterface()
{
    std::lock_guard<std::mutex> guard(mtx_);
    return powerInterface_;
}
#endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
} // namespace MMI
} // namespace OHOS