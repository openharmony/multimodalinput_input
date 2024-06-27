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

#include "hdf_device_event_manager.h"

#include <dlfcn.h>
#include <unistd.h>

#include "hdf_device_event_dispatch.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "HdfDeviceEventManager"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INPUT_PARAM_FIRST { 0 };
constexpr int32_t INPUT_PARAM_SECOND { 1 };
} // namespace
void HdfDeviceEventManager::ConnectHDFInit()
{
    std::string name = "mmi-hdf";
    inputInterface_ = IInputInterfaces::Get(true);
    if (inputInterface_ == nullptr) {
        MMI_HILOGE("The inputInterface_ is nullptr");
        return;
    }
    thread_ = std::thread([this] { injectThread_.InjectFunc(); });
    pthread_setname_np(thread_.native_handle(), name.c_str());
    int32_t ret = inputInterface_->OpenInputDevice(TOUCH_DEV_ID);
    if (ret == HDF_SUCCESS) {
        ret = inputInterface_->GetInputDevice(TOUCH_DEV_ID, iDevInfo_);
        if (ret != HDF_SUCCESS) {
            MMI_HILOGE("Get input device failed");
            return;
        }
        callback_ = new (std::nothrow) HdfDeviceEventDispatch(iDevInfo_.attrSet.axisInfo[ABS_MT_POSITION_X].max,
            iDevInfo_.attrSet.axisInfo[ABS_MT_POSITION_Y].max);
        if (callback_ == nullptr) {
            MMI_HILOGE("The callback_ is nullptr");
            return;
        }
        ret = inputInterface_->RegisterReportCallback(TOUCH_DEV_ID, callback_);
        MMI_HILOGD("RegisterReportCallback ret:%{public}d", ret);
    } else {
        MMI_HILOGE("Open input device failed");
    }
}
} // namespace MMI
} // namespace OHOS

int32_t main() __attribute__((no_sanitize("cfi")))
{
    int sleepSeconds = 1;
    sleep(sleepSeconds);
    OHOS::MMI::HdfDeviceEventManager iHdfDeviceEventManager;
    iHdfDeviceEventManager.ConnectHDFInit();

    int32_t pid = getpid();
    MMI_HILOGI("Current pid:%{public}d", pid);
    void *notifyProcessStatus = nullptr;
    int32_t(* notifyProcessStatusFunc)(int32_t, int32_t, int32_t) = nullptr;
    void *libMemMgrClientHandle = dlopen("libmemmgrclient.z.so", RTLD_NOW);
    if (!libMemMgrClientHandle) {
        MMI_HILOGE("%{public}s, dlopen libmemmgrclient failed.", __func__);
        goto nextStep;
    }

    notifyProcessStatus = (dlsym(libMemMgrClientHandle, "notify_process_status"));
    if (!notifyProcessStatus) {
        MMI_HILOGE("%{public}s, dlsym notify_process_status failed.", __func__);
        dlclose(libMemMgrClientHandle);
        goto nextStep;
    }
    notifyProcessStatusFunc = reinterpret_cast<int32_t(*)(int32_t, int32_t, int32_t)>(notifyProcessStatus);
    if (notifyProcessStatusFunc(pid, OHOS::MMI::INPUT_PARAM_FIRST, OHOS::MMI::INPUT_PARAM_SECOND) != 0) {
        MMI_HILOGE("%{public}s, get device memory failed.", __func__);
    }
    dlclose(libMemMgrClientHandle);
    MMI_HILOGI("notify_process_status execute end");

nextStep:
    MMI_HILOGI("start thread loop");
    static std::int32_t usleepTime = 1500000;
    while (true) {
        usleep(usleepTime);
    }
    return 0;
}
