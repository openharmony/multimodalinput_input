/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <cstring>
#include <functional>

#include <unistd.h>

#include "hilog/log.h"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMIS {
namespace {
    constexpr HiLogLabel LABEL = { LOG_CORE, 0xD002800, "HdfDeviceEventManager" };
}

HdfDeviceEventManager::HdfDeviceEventManager() {}

HdfDeviceEventManager::~HdfDeviceEventManager() {}

void HdfDeviceEventManager::ConnectHDFInit()
{
    uint32_t ret = GetInputInterface(&inputInterface_);
    if (ret != 0) {
        HiLog::Error(LABEL, "Initialize %{public}s fail! ret is %{public}u", __func__, ret);
        return;
    }

    if (inputInterface_ == nullptr || inputInterface_->iInputManager == nullptr) {
        HiLog::Error(LABEL, "%{public}s inputInterface_ or iInputManager is NULL", __func__);
        return;
    }

    thread_ = std::thread(&InjectThread::InjectFunc, injectThread_);
    ret = inputInterface_->iInputManager->OpenInputDevice(TOUCH_DEV_ID);
    if ((ret == INPUT_SUCCESS) && (inputInterface_->iInputReporter != nullptr)) {
        ret = inputInterface_->iInputManager->GetInputDevice(TOUCH_DEV_ID, &iDevInfo_);
        if (ret != INPUT_SUCCESS) {
            HiLog::Error(LABEL, "%{public}s GetInputDevice error %{public}d", __func__, ret);
            return;
        }
        std::unique_ptr<HdfDeviceEventDispatch> hdf = std::make_unique<HdfDeviceEventDispatch>(\
            iDevInfo_->attrSet.axisInfo[ABS_MT_POSITION_X].max, iDevInfo_->attrSet.axisInfo[ABS_MT_POSITION_Y].max);
        if (hdf == nullptr) {
            HiLog::Error(LABEL, "%{public}s hdf is nullptr", __func__);
            return;
        }
        callback_.EventPkgCallback = hdf->GetEventCallbackDispatch;
        ret = inputInterface_->iInputReporter->RegisterReportCallback(TOUCH_DEV_ID, &callback_);
    }
}
}  // namespace MMIS
}  // namespace OHOS

int32_t main()
{
    static std::int32_t usleepTime = 1500000;
    HiLog::Info(OHOS::MMIS::LABEL, "%{public}s running !", __func__);
    OHOS::MMIS::HdfDeviceEventManager iHdfDeviceEventManager;
    iHdfDeviceEventManager.ConnectHDFInit();
    while (true) {
        usleep(usleepTime);
    }
    return 0;
}
