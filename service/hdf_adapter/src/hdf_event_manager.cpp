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

#include "hdf_event_manager.h"
#include <cstring>
#include <ctime>
#include <thread>
#include <sys/time.h>
#include <unistd.h>
#include "hdf_inject_init.cpp"
#include "lib_hdf.h"
#include "libmmi_util.h"
#include "mmi_log.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "HdfEventManager"};
} // namespace

HdfEventManager *HdfEventManager::m_globleThis;
int32_t HdfEventManager::EvdevSimIoctl(int32_t hdindex, int32_t pcmd, void *iobuff)
{
    const int32_t size = (pcmd >> IOCTL_CMD_SHIFT) & IOCTL_CMD_MASK;
    int32_t cmd = pcmd & 0xff;

    MMI_LOGD("evdev_simioctl index:%{public}d,cmd:%{public}02x,size:%{public}d,"
             "pcmd:%{public}04x", hdindex, cmd, size, pcmd);
    DrvType drvtype = g_index2DrvType[hdindex - MAX_INPUT_DEVICE_COUNT];
    MMI_LOGD("evdev_simioctl drvtype:%{public}d", drvtype);
    if (drvtype >= INVALD) {
        MMI_LOGE("Unknown device type");
        return 0;
    }
    for (const auto &item : m_globleThis->hdflist_) {
        if (item.index == hdindex) {
            break;
        }
    }
    const int32_t iobuffSize = size;
    int32_t ret = 0;
    switch (cmd) {
        case IO_BITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayBits[drvtype], size);
            break;
        case IO_KEYBITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayKeyBits[drvtype], size);
            break;
        case IO_RELBITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayRelBits[drvtype], size);
            break;
        case IO_ABSBITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayAbsBits[drvtype], size);
            break;
        case IO_MSCBITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayMscBits[drvtype], size);
            break;
        case IO_SWBITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arraySwBits[drvtype], size);
            break;
        case IO_LEDBITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayLedBits[drvtype], size);
            break;
        case IO_SNDBITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arraySndBits[drvtype], size);
            break;
        case IO_PROPBITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayPropsBits[drvtype], size);
            break;
        case IO_KEYVALUES:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayKeyValues[drvtype], size);
            break;
        case IO_LEDVALUES:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayLedValues[drvtype], size);
            break;
        case IO_SWVALUES:
            ret = memcpy_s(iobuff, iobuffSize, &g_arraySwValues[drvtype], size);
            break;
        case IO_MTVABS:
            break;
        case IO_IDS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayIds[drvtype], size);
            break;
        case IO_FFBITS:
            ret = memcpy_s(iobuff, iobuffSize, &g_arrayFfBits[drvtype], size);
            break;
        default:
            if (cmd >= IO_ABSBEGIN && cmd < IO_ABEND) {
                ret = memcpy_s(iobuff, iobuffSize, &g_arrayAxisInfo[drvtype][cmd - IO_ABSBEGIN], size);
            }
            break;
    }
    if (ret != EOK) {
        MMI_LOGE("call memcpy_s fail, cmd = %d, ret = %d", cmd, ret);
    }
    return RET_OK;
}
int32_t HdfEventManager::EvdevIoctl(int32_t hdiindex, int32_t pcmd, void *iobuff)
{
    int32_t size = (pcmd >> IOCTL_CMD_SHIFT) & IOCTL_CMD_MASK;
    int32_t cmd = pcmd & 0xff;
    MMI_LOGD("index:%{public}d,cmd:%{public}02x,size:%{public}d,"
        "pcmd:%{public}04x", hdiindex, cmd, size, pcmd);
    DeviceInfo *deviceinfo = nullptr;
    for (auto &item : globleThis_->hdflist_){
        if (item.index == hdiindex) {
            deviceinfo = static_cast<DeviceInfo*>(item->deviceinfo);
            break;
        }
    }
    if (deviceinfo == nullptr) {
        MMI_LOGE("Deviceinfo is null");
        return 0;
    }
    const int32_t iobuffSize = size;
    int32_t ret = 0;
    switch (cmd) {
        case IO_BITS:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.eventType, size);
            break;
        case IO_KEYBITS:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.keyCode, size);
            break;
        case IO_RELBITS:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.relCode, size);
            break;
        case IO_ABSBITS:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.absCode, size);
            break;
        case IO_MSCBITS:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.miscCode, size);
            break;
        case IO_SWBITS:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.switchCode, size);
            break;
        case IO_LEDBITS:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.ledCode, size);
            break;
        case IO_SNDBITS:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.forceCode, size);
            break;
        case IO_PROPBITS:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.devProp, size);
            break;
        case IO_KEYVALUES:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.keyType, size);
            break;
        case IO_LEDVALUES:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.ledType, size);
            break;
        case IO_SWVALUES:
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.switchType, size);
            break;
        case IO_MTVABS:
            break;
        case IO_IDS:
            ret = memcpy_s(iobuff, iobuffSize, &deviceinfo->attrSet.id, size);
            break;
        case IO_FFBITS:
            ret = memcpy_s(iobuff, iobuffSize, &deviceinfo->abilitySet.forceCode, size);
            break;
        default:
            if (cmd >= IO_ABSBEGIN && cmd < IO_ABEND) {
                ret = memcpy_s(iobuff, iobuffSize, &deviceinfo->attrSet.axisInfo[cmd - IO_ABSBEGIN], size);
            }
            break;
    }
    if (ret != EOK) {
        MMI_LOGE("call memcpy_s fail, cmd = %d, ret = %d", cmd, ret);
    }
    return 0;
}

HdfEventManager::HdfEventManager()
{
    globleThis_ = this;
    hdiinput_ = nullptr;
}
HdfEventManager::~HdfEventManager()
{
    uint32_t ret = inputInterface_->iInputReporter->UnregisterHotPlugCallback();
    if (ret == INPUT_SUCCESS) {
        MMI_LOGI("%{public}s:%{public}d INPUT_SUCCESS", __func__, __LINE__);
    } else {
        MMI_LOGE("%{public}s:%{public}d INPUT_ERROR", __func__, __LINE__);
    }
}
int32_t HdfEventManager::HdfdevtypeMapLibinputType(uint32_t devIndex, uint32_t devType)
{
    if (devIndex >= MAX_INPUT_DEVICE_COUNT) {
        MMI_LOGE("The maximum number of devices exceeded, devIndex:%{public}d", devIndex);
        return devType;
    }
    int32_t ret = 0;
    switch (devType) {
        case INDEV_TYPE_TOUCH:
            ret = HDF_INPUT | HDF_TOUCHSCREEN;
            break;
        case INDEV_TYPE_MOUSE:
            ret = HDF_INPUT | HDF_MOUSE;
            break;
        case INDEV_TYPE_KEYBOARD:
            ret = HDF_INPUT | HDF_KEYBOARD;
            break;
        default:
            ret = devType;
    }
    return ret;
}
#ifdef  OHOS_BUILD_HDF
int32_t HdfEventManager::GetDeviceCount()
{
    int32_t ret = memset_s(mountDevIndex_, sizeof(DevDesc) * TOTAL_INPUT_DEVICE_COUNT, 0,
                           sizeof(DevDesc) * TOTAL_INPUT_DEVICE_COUNT);
    if (ret != EOK) {
        MMI_LOGE("call memset_s fail. ret = %d", ret);
    }
    int32_t devcount = 0;
    if (inputInterface_ != nullptr || inputInterface_->iInputManager != nullptr) {
        int32_t ret = inputInterface_->iInputManager->ScanInputDevice(MAX_INPUT_DEVICE_COUNT, mountDevIndex_);
        if (ret) {
            MMI_LOGE("%{public}s:%{public}d Error:ScanInputDevice failed", __func__, __LINE__);
            return 0;
        }

        for (int32_t i = 0; i < MAX_INPUT_DEVICE_COUNT; i++) {
            if (mountDevIndex_[i].devIndex != 0) {
                devcount = devcount + 1;
            }
        }
    }
    int32_t jectcount = 0;
    if (injectInterface_ != nullptr || injectInterface_->iInputManager != nullptr) {
        int32_t ret = injectInterface_->iInputManager->ScanInputDevice(MAX_INPUT_DEVICE_COUNT,
                                                                       &mountDevIndex_[devcount]);
        if (ret) {
            MMI_LOGE("%{public}s:%{public}d Error:injectInterface_ ScanInputDevice failed",
                __func__, __LINE__);
            return devcount;
        }

        for (int32_t i = 0; i < MAX_INPUT_DEVICE_COUNT; i++) {
            if (mountDevIndex_[devcount + i].devIndex != 0) {
                jectcount = jectcount + 1;
            }
        }
    }
    return devcount + jectcount;
}
void HdfEventManager::SetupCallback()
{
    MMI_LOGD("%{public}s:%{public}d ThreadSetupCallback start", __func__, __LINE__);
    uint32_t ret = GetInputInterface(&inputInterface_);
    if (ret != 0 || inputInterface_ == nullptr
        || inputInterface_->iInputManager == nullptr
        || inputInterface_->iInputReporter == nullptr) {
        MMI_LOGD("%{public}s:%{public}d inputInterface_ init fail", __func__, __LINE__);
    }

    ret = GetInputInterfaceFromInject(&injectInterface_);
    if (ret != 0 || injectInterface_ == nullptr
        || injectInterface_->iInputManager == nullptr
        || injectInterface_->iInputReporter == nullptr) {
        MMI_LOGD("%{public}s:%{public}d injectInterface_ init fail", __func__, __LINE__);
    }

    eventCallBack_.EventPkgCallback = globleThis_->GetEventCallback;
    hostPlugCallBack_.HotPlugCallback = globleThis_->HotPlugCallback;
    if (inputInterface_) {
        ret = inputInterface_->iInputReporter->RegisterHotPlugCallback(&hostPlugCallBack_);
        if (ret == INPUT_SUCCESS) {
            MMI_LOGI("%{public}s:%{public}d RegisterHotPlugCallback INPUT_SUCCESS", __func__, __LINE__);
        } else {
            MMI_LOGE("%{public}s:%{public}d RegisterHotPlugCallback INPUT_ERROR", __func__, __LINE__);
        }
    }

    if (injectInterface_) {
        ret = injectInterface_->iInputReporter->RegisterHotPlugCallback(&hostPlugCallBack_);
        if (ret == INPUT_SUCCESS) {
            MMI_LOGI("%{public}s:%{public}d injectInterface_ RegisterHotPlugCallback INPUT_SUCCESS",
                __func__, __LINE__);
        } else {
            MMI_LOGE("%{public}s:%{public}d injectInterface_ RegisterHotPlugCallback INPUT_ERROR",
                __func__, __LINE__);
        }
    }

    int32_t count = GetDeviceCount();
    MMI_LOGD("ThreadSetupCallback count:%{public}d",                                 count);
    for (int32_t i = 0; i < count; i++) {
        DeviceAddHandle(mountDevIndex_[i].devIndex, mountDevIndex_[i].devType);
    }
}

void HdfEventManager::AddDevice(uint32_t devIndex, uint32_t devType)
{
    uint32_t ret = 0;
    if (devIndex >= MAX_INPUT_DEVICE_COUNT) {
        ret = injectInterface_->iInputReporter->RegisterReportCallback(devIndex, &eventCallBack_);
        return;
    }
    if (!OpenHdfDevice(devIndex, true)) {
        return;
    }
    ret = inputInterface_->iInputReporter->RegisterReportCallback(devIndex, &eventcallback);
    if (ret == INPUT_SUCCESS) {
        MMI_LOGI("%{public}s:%{public}d RegisterReportCallback eventcallback INPUT_SUCCESS"
            "devindex:%{public}u, devType:%{public}u", __func__, __LINE__, devIndex, devType);
    } else {
        MMI_LOGE("%{public}s:%{public}d RegisterReportCallback eventcallback INPUT_ERROR"
            "devindex:%{public}u,devType:%{public}u", __func__, __LINE__, devIndex, devType);
    }
}
bool HdfEventManager::OpenHdfDevice(uint32_t devIndex, bool oper)
{
    if (devIndex >= MAX_INPUT_DEVICE_COUNT) {
        return true;
    }
    int32_t ret = -1;
    if (oper) {
        ret = inputInterface_->iInputManager->OpenInputDevice(devIndex);
    } else {
        ret = inputInterface_->iInputManager->CloseInputDevice(devIndex);
    }
    if (ret == 0) {
        MMI_LOGI("%{public}s:%{public}d Info: device success!", __func__, __LINE__);
        return true;
    }

    if (ret != 0) {
        MMI_LOGE("%{public}s:%{public}d Error: device fail! code:%{public}u", __func__, __LINE__, ret);
    }
    return false;
}
void HdfEventManager::HotPlugCallback(const HotPlugEvent *event)
{
    MMI_LOGD("%{public}s:%{public}d HotPlugCallback status:%{public}u,devindex:%{public}u"
        "devType:%{public}u", __func__, __LINE__, event->status, event->devIndex, event->devType);

    if (!event->status) {
        DeviceAddHandle(event->devIndex, event->devType);
    } else {
        DeviceRemoveHandle(event->devIndex, event->devType);
    }
}
int32_t HdfEventManager::DeviceRemoveHandle(uint32_t devIndex, uint32_t devType)
{
    MMI_LOGD("%{public}s:%{public}d DeviceRemoveHandle devindex:%{public}u,devType:%{public}u",
        __func__, __LINE__, devIndex, devType);
    Devcmd cmd;
    cmd.index = devIndex;
    cmd.cmd = static_cast<int32_t>(HDF_RMV_DEVICE);
    libinput_devpipe_write(m_globleThis->hdiinput_, &cmd, sizeof(Devcmd));
    if (devIndex < MAX_INPUT_DEVICE_COUNT) {
        uint32_t ret = m_globleThis->inputInterface_->iInputReporter->UnregisterReportCallback(devIndex);
        if (ret == INPUT_SUCCESS) {
            MMI_LOGI("%{public}s:%{public}d REMOVE_SUCCESS devindex:%{public}u,devType:%{public}u",
                __func__, __LINE__, devIndex, devType);
        } else {
            MMI_LOGE("%{public}s:%{public}d REMOVE_ERROR devindex:%{public}u,devType:%{public}u",
                __func__, __LINE__, devIndex, devType);
        }
    }
    globleThis_->OpenHdfDevice(devIndex, false);
    return RET_OK;
}


void HdfEventManager::GetEventCallback(const EventPackage **pkgs, uint32_t count, uint32_t devIndex)
{
    constexpr uint16_t byteSize = 8;
    CHKPV(pkgs);
    struct input_event eventarry[MAX_EVENT_PKG_NUM];
    for (uint32_t i = 0; i < count && i < MAX_EVENT_PKG_NUM; i++) {
        eventarry[i].code = pkgs[i]->code;
        eventarry[i].type = (pkgs[i]->type) | static_cast<uint16_t>(devIndex<<byteSize); // 不改变livinput结构传递，对象的index参数
        eventarry[i].value = pkgs[i]->value;
        eventarry[i].input_event_sec = (pkgs[i]->timestamp) / (USEC_PER_SEC);
        eventarry[i].input_event_usec = (pkgs[i]->timestamp) % (USEC_PER_SEC);
    }
    if (!globleThis_->devStatus[devIndex]) {
        return;
    }
    libinput_pipe_write(globleThis_->hdiinput_, devIndex, eventarry, count * sizeof(struct input_event));
}
int32_t HdfEventManager::DeviceAddHandle(uint32_t devIndex, uint32_t devType)
{
    MMI_LOGD("%{public}s:%{public}d DeviceAddHandle devindex:%{public}u,devType:%{public}u",
        __func__, __LINE__, devIndex, devType);
    globleThis_->devStatus[devIndex] = false;
    uhdf *hdiuhdf = nullptr;
    hdiuhdf = new(uhdf);
    hdiuhdf->index = devIndex;
    hdiuhdf->type = globleThis_->HdfdevtypeMapLibinputType(devIndex, devType);
    hdiuhdf->nproperties = 0;
    hdiuhdf->quirkpop = nullptr;
    hdiuhdf->modeltype = 0;
    hdiuhdf->fn = (hdiuhdf->index >= MAX_INPUT_DEV_NUM) ? EvdevSimIoctl : EvdevIoctl;
    globleThis_->hdflist_.push_back(hdiuhdf);
    Devcmd cmd;
    cmd.index = devIndex;
    cmd.cmd = static_cast<int32_t>(HDF_ADD_DEVICE);
    libinput_devpipe_write(globleThis_->hdiinput_, &cmd, sizeof(Devcmd));
    return RET_OK;
}
constexpr struct libinput_interface _hdfinterface = {
    .open_restricted = [](const char *path, int32_t flags, void *user_data)->int32_t {
        int32_t fd = -1;
        MMI_LOGD("libinput .open_restricted path:%{public}s,fd:%{public}d", path, fd);
        return fd < 0 ? -errno : fd;
    },
    .close_restricted = [](int32_t fd, void *user_data)
    {
        MMI_LOGD("libinput .close_restricted fd:%{public}d", fd);
    },
};
libinput *HdfEventManager::HdfLibinputInit()
{
    if (globleThis_->hdiinput_ == nullptr) {
        globleThis_->hdiinput_ = libinput_hdf_create_context(&_hdfinterface, nullptr);
    }
    MMI_LOGD("HdfLibinputInit function end");
    return globleThis_->hdiinput_;
}
int32_t HdfEventManager::HdfDevHandle(int32_t index, hdf_event_type cmd)
{
    if (cmd != HDF_ADD_DEVICE) {
        MMI_LOGD("HdfRmv function start");
        uhdf *hdiuhdf = nullptr;
        for (std::list<uhdf*>::iterator it = globleThis_->hdflist_.begin();
             it != globleThis_->hdflist_.end(); ++it) {
            uhdf *hdiuhdfit = *it;
            if (hdiuhdfit->index == static_cast<int32_t>(index)) {
                hdiuhdf = *it;
                globleThis_->hdflist_.remove(*it);
                break;
            }
        }
        if (hdiuhdf == nullptr) {
            return RET_OK;
        }
        uhdfdevice_removed(hdiuhdf);
        delete(hdiuhdf);
        return RET_OK;
    }

    uhdf *hdiuhdf = nullptr;
    for (std::list<uhdf*>::iterator it = globleThis_->hdflist_.begin();
        it != globleThis_->hdflist_.end(); ++it) {
        uhdf *hdiuhdfit = *it;
        if (hdiuhdfit->index != static_cast<int32_t>(index)) {
            continue;
        }

        hdiuhdf = *it;
        DeviceInfo *deviceinfo = nullptr;
        globleThis_->AddDevice(index, hdiuhdf->type);
        if (index < MAX_INPUT_DEVICE_COUNT) {
            uint32_t ret = globleThis_->inputInterface_->iInputManager->GetInputDevice(index, &deviceinfo);
            if (ret != 0 || (deviceinfo == nullptr)) {
                MMI_LOGE("%{public}s:%{public}d inputInterface_ GetInputDevice ret:%{public}d",
                         __func__, __LINE__, ret);
                return RET_ERR;
            }
            hdiuhdf->deviceinfo = (void*)deviceinfo;
        }
        uhdfdevice_added(globleThis_->hdiinput_, hdiuhdf, "default");
        globleThis_->devStatus[index] = true;
        return RET_OK;
    }
    return RET_OK;
}
bool HdfEventManager::Init()
{
    return true;
}
HdfEventManager  hdfEventManager;
extern "C" libinput *HdfAdfInit()
{
    MMI_LOGD("HdfAdfInit function start");
    return hdfEventManager.HdfLibinputInit();
}

extern "C" int32_t HdfDevHandle(int32_t index, hdf_event_type cmd)
{
    MMI_LOGD("HdfDevHandle function start index:%{public}d,cmd:%{public}d", index, cmd);
    return hdfEventManager.HdfDevHandle(index, cmd);
}
#endif
} // namespace MMI
} // namespace OHOS