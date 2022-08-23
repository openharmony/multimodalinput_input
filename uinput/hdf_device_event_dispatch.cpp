/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hdf_device_event_dispatch.h"

#include <memory>

#include "mmi_log.h"
#include "virtual_touch_screen.h"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "HdfDeviceEventDispatch"};
} // namespace
std::unique_ptr<VirtualTouchScreen> g_pTouchScreen = nullptr;
InjectThread HdfDeviceEventDispatch::injectThread_;

HdfDeviceEventDispatch::HdfDeviceEventDispatch(const uint32_t maxX, const uint32_t maxY)
{
    g_pTouchScreen = std::make_unique<VirtualTouchScreen>(maxX, maxY);
    g_pTouchScreen->SetUp();
}

HdfDeviceEventDispatch::~HdfDeviceEventDispatch() {}

void HdfDeviceEventDispatch::GetEventCallbackDispatch(
    const InputEventPackage **pkgs, uint32_t count, uint32_t devIndex)
{
    if (pkgs == nullptr) {
        MMI_HILOGE("The pkgs is nullptr");
        return;
    }
    for (uint32_t i = 0; i < count; i++) {
        if (pkgs[i] == nullptr) {
            continue;
        }
        if ((pkgs[i]->type == 0) && (pkgs[i]->code == 0) && (pkgs[i]->value == 0)) {
            InjectInputEvent injectInputSync = {injectThread_.TOUCH_SCREEN_DEVICE_ID, 0, SYN_MT_REPORT, 0};
            injectThread_.WaitFunc(injectInputSync);
        }
        InjectInputEvent injectInputEvent = {
            injectThread_.TOUCH_SCREEN_DEVICE_ID,
            pkgs[i]->type,
            pkgs[i]->code,
            pkgs[i]->value
        };
        injectThread_.WaitFunc(injectInputEvent);
    }
}
} // namespace MMI
} // namespace OHOS
