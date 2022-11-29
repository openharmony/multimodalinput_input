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

#include "hdf_device_event_manager.h"

#include <unistd.h>

#include "hdf_device_event_dispatch.h"
#include "mmi_log.h"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "HdfDeviceEventManager"};
} // namespace

HdfDeviceEventManager::HdfDeviceEventManager() {}

HdfDeviceEventManager::~HdfDeviceEventManager() {}

void HdfDeviceEventManager::ConnectHDFInit()
{
    int32_t ret = GetInputInterface(&inputInterface_);
    if (ret != 0) {
        MMI_HILOGE("Initialize failed");
        return;
    }

    if (inputInterface_ == nullptr || inputInterface_->iInputManager == nullptr) {
        MMI_HILOGE("The inputInterface_ or iInputManager is nullptr");
        return;
    }

    thread_ = std::thread(&InjectThread::InjectFunc, injectThread_);
    ret = inputInterface_->iInputManager->OpenInputDevice(TOUCH_DEV_ID);
    if ((ret == INPUT_SUCCESS) && (inputInterface_->iInputReporter != nullptr)) {
        ret = inputInterface_->iInputManager->GetInputDevice(TOUCH_DEV_ID, &iDevInfo_);
        if (ret != INPUT_SUCCESS) {
            MMI_HILOGE("GetInputDevice error");
            return;
        }
        std::unique_ptr<HdfDeviceEventDispatch> hdf = std::make_unique<HdfDeviceEventDispatch>(\
            iDevInfo_->attrSet.axisInfo[ABS_MT_POSITION_X].max, iDevInfo_->attrSet.axisInfo[ABS_MT_POSITION_Y].max);
        callback_.EventPkgCallback = hdf->GetEventCallbackDispatch;
        ret = inputInterface_->iInputReporter->RegisterReportCallback(TOUCH_DEV_ID, &callback_);
        MMI_HILOGD("RegisterReportCallback ret:%{public}d", ret);
    }
}
} // namespace MMI
} // namespace OHOS
int32_t main()
{
    int sleepSeconds = 1;
    sleep(sleepSeconds);
    OHOS::MMI::HdfDeviceEventManager iHdfDeviceEventManager;
    iHdfDeviceEventManager.ConnectHDFInit();
    static std::int32_t usleepTime = 1500000;
    while (true) {
        usleep(usleepTime);
    }
    return 0;
}
