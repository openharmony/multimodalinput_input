/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "hdf_device_event_dispatch.h"

#include <memory>

#include "mmi_log.h"
#include "virtual_touch_screen.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "HdfDeviceEventDispatch"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMI {
std::unique_ptr<VirtualTouchScreen> g_pTouchScreen = nullptr;
InjectThread HdfDeviceEventDispatch::injectThread_;

HdfDeviceEventDispatch::HdfDeviceEventDispatch(const uint32_t maxX, const uint32_t maxY)
{
    g_pTouchScreen = std::make_unique<VirtualTouchScreen>(maxX, maxY);
    g_pTouchScreen->SetUp();
}

HdfDeviceEventDispatch::~HdfDeviceEventDispatch() {}

int32_t HdfDeviceEventDispatch::EventPkgCallback(const std::vector<EventPackage> &pkgs, uint32_t devIndex)
{
    if (pkgs.empty()) {
        MMI_HILOGE("The pkgs is empty");
        return HDF_FAILURE;
    }

    for (const auto &item : pkgs) {
        if ((item.type == 0) && (item.code == 0) && (item.value == 0)) {
            InjectInputEvent injectInputSync = { injectThread_.TOUCH_SCREEN_DEVICE_ID, 0, SYN_MT_REPORT, 0 };
            injectThread_.WaitFunc(injectInputSync);
        }
        InjectInputEvent injectInputEvent = {
            injectThread_.TOUCH_SCREEN_DEVICE_ID,
            item.type,
            item.code,
            item.value
        };
        injectThread_.WaitFunc(injectInputEvent);
    }
    return HDF_SUCCESS;
}

int32_t HdfDeviceEventDispatch::HotPlugCallback(const HotPlugEvent &event)
{
    return HDF_SUCCESS;
}
} // namespace MMI
} // namespace OHOS