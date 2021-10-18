/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <thread>
#include <unistd.h>

#include <thread>
#include <ctime>
#include <sys/time.h>

#include "libmmi_util.h"
#include "log.h"
#include "lib_hdf.h"
#include "hdf_inject_init.cpp"
#include "util.h"

namespace {
    using namespace OHOS::MMI;
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "HdfEventManager"};
}

OHOS::MMI::HdfEventManager *OHOS::MMI::HdfEventManager::m_globleThis;
int OHOS::MMI::HdfEventManager::EvdevSimIoctl(int hdindex, int pcmd, void *iobuff)
{
    uhdf *hdiuhdf = nullptr;
    const int size = (pcmd >> IOCTL_CMD_SHIFT) & IOCTL_CMD_MASK;
    const int iobuffSize = size;
    int cmd = pcmd & 0xff;

    MMI_LOGD("----evdev_simioctl %{public}p,index =%{public}d,cmd = %{public}02x: size =%{public}d "
             "pcmd = %{public}04x ---",
             iobuff, hdindex, cmd, size, pcmd);
    DrvType drvtype = index2DrvType[hdindex - MAX_INPUT_DEVICE_COUNT];
    MMI_LOGD("----evdev_simioctl drvtype =%{public}d", drvtype);
    if (drvtype >= INVALD) {
        return 0;
    }
    for (std::list<uhdf*>::iterator it = m_globleThis->hdflist_.begin(); it != m_globleThis->hdflist_.end(); ++it) {
        hdiuhdf = *it;
        if (hdiuhdf->index == hdindex) {
            break;
        }
    }
    int ret = 0;
    switch (cmd) {
        case IO_BITS: // bits
            ret = memcpy_s(iobuff, iobuffSize, &arrayBits[drvtype], size);
            break;
        case IO_KEYBITS: // key_bits
            ret = memcpy_s(iobuff, iobuffSize, &arrayKeyBits[drvtype], size);
            break;
        case IO_RELBITS: // rel_bits
            ret = memcpy_s(iobuff, iobuffSize, &arrayRelBits[drvtype], size);
            break;
        case IO_ABSBITS: // abs_bits
            ret = memcpy_s(iobuff, iobuffSize, &arrayAbsBits[drvtype], size);
            break;
        case IO_MSCBITS: // msc_bits
            ret = memcpy_s(iobuff, iobuffSize, &arrayMscBits[drvtype], size);
            break;
        case IO_SWBITS: // sw_bits
            ret = memcpy_s(iobuff, iobuffSize, &arraySwBits[drvtype], size);
            break;
        case IO_LEDBITS: // led_bits
            ret = memcpy_s(iobuff, iobuffSize, &arrayLedBits[drvtype], size);
            break;
        case IO_SNDBITS: // snd_bits
            ret = memcpy_s(iobuff, iobuffSize, &arraySndBits[drvtype], size);
            break;
        case IO_PROPBITS: // poops
            ret = memcpy_s(iobuff, iobuffSize, &arrayPropsBits[drvtype], size);
            break;
        case IO_KEYVALUES: // key_values
            ret = memcpy_s(iobuff, iobuffSize, &arrayKeyValues[drvtype], size);
            break;
        case IO_LEDVALUES: // led_values
            ret = memcpy_s(iobuff, iobuffSize, &arrayLedValues[drvtype], size);
            break;
        case IO_SWVALUES: // sw_values
            ret = memcpy_s(iobuff, iobuffSize, &arraySwValues[drvtype], size);
            break;
        case IO_MTVABS: // mtv abs
            break;
        case IO_IDS:  // ids
            ret = memcpy_s(iobuff, iobuffSize, &arrayIds[drvtype], size);
            break;
        case IO_FFBITS: // ff bits
            ret = memcpy_s(iobuff, iobuffSize, &arrayFfBits[drvtype], size);
            break;
        default:
            if (cmd >= IO_ABSBEGIN && cmd < IO_ABEND) {
                ret = memcpy_s(iobuff, iobuffSize, &arrayAxisInfo[drvtype][cmd - IO_ABSBEGIN], size);
            }
            break;
    }
    if (ret != EOK) {
        MMI_LOGE("call memcpy_s fail, cmd = %d, ret = %d", cmd, ret);
    }
    return 0;
}
int OHOS::MMI::HdfEventManager::EvdevIoctl(int hdiindex, int pcmd, void *iobuff)
{
    uhdf *hdiuhdf = nullptr;
    int size = (pcmd >> IOCTL_CMD_SHIFT) & IOCTL_CMD_MASK;
    const int iobuffSize = size;
    int cmd = pcmd & 0xff;
    DeviceInfo *deviceinfo = nullptr;
    MMI_LOGD("----evdev_ioctl %{public}p,index =%{public}d,cmd = %{public}02x: size =%{public}d  "
        "pcmd = %{public}04x ---", iobuff, hdiindex, cmd, size, pcmd);
    for (std::list<uhdf*>::iterator it = m_globleThis->hdflist_.begin();
        it != m_globleThis->hdflist_.end(); ++it) {
        hdiuhdf = *it;
        if (hdiuhdf->index == hdiindex) {
            deviceinfo = (DeviceInfo*)hdiuhdf->deviceinfo;
            break;
        }
    }
    if (deviceinfo == nullptr) {
        return 0;
    }
    int ret = 0;
    switch (cmd) {
        case IO_BITS: // bits
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.eventType, size);
            break;
        case IO_KEYBITS: // key_bits
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.keyCode, size);
            break;
        case IO_RELBITS: // rel_bits
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.relCode, size);
            break;
        case IO_ABSBITS: // abs_bits
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.absCode, size);
            break;
        case IO_MSCBITS: // msc_bits
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.miscCode, size);
            break;
        case IO_SWBITS: // sw_bits
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.switchCode, size);
            break;
        case IO_LEDBITS: // led_bits
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.ledCode, size);
            break;
        case IO_SNDBITS: // snd_bits
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.forceCode, size);
            break;
        case IO_PROPBITS: // poops
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.devProp, size);
            break;
        case IO_KEYVALUES: // key_values
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.keyType, size);
            break;
        case IO_LEDVALUES: // led_values
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.ledType, size);
            break;
        case IO_SWVALUES: // sw_values
            ret = memcpy_s(iobuff, iobuffSize, deviceinfo->abilitySet.switchType, size);
            break;
        case IO_MTVABS: // mtv abs
            break;
        case IO_IDS:  // ids
            ret = memcpy_s(iobuff, iobuffSize, &deviceinfo->attrSet.id, size);
            break;
        case IO_FFBITS: // ff bits
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

OHOS::MMI::HdfEventManager::HdfEventManager()
{
    m_globleThis = this;
    hdiinput_ = nullptr;
}
OHOS::MMI::HdfEventManager::~HdfEventManager()
{
    uint32_t ret = inputInterface_->iInputReporter->UnregisterHotPlugCallback();
    if (ret == INPUT_SUCCESS) {
        MMI_LOGI("---- %{public}s:%{public}d UnregisterHotPlugCallback INPUT_SUCCESS  \n", __func__, __LINE__);
    } else {
        MMI_LOGE("---- %{public}s:%{public}d UnregisterHotPlugCallback INPUT_ERROR \n", __func__, __LINE__);
    }
}
int OHOS::MMI::HdfEventManager::HdfdevtypeMapLibinputType(uint32_t devIndex, uint32_t devType)
{
    int ret = 0;
    if (devIndex >= MAX_INPUT_DEVICE_COUNT) {
        return devType;
    }
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
int OHOS::MMI::HdfEventManager::GetDeviceCount()
{
    int devcount = 0;
    int ret = memset_s(mountDevIndex_, sizeof(DevDesc) * TOTAL_INPUT_DEVICE_COUNT, 0,
                       sizeof(DevDesc) * TOTAL_INPUT_DEVICE_COUNT);
    if (ret != EOK) {
        MMI_LOGE("call memset_s fail. ret = %d", ret);
    }
    if (inputInterface_ != nullptr || inputInterface_->iInputManager != nullptr) {
        int32_t ret = inputInterface_->iInputManager->ScanInputDevice(mountDevIndex_, MAX_INPUT_DEVICE_COUNT);
        if (ret) {
            MMI_LOGE("---- %{public}s:%{public}d Error:ScanInputDevice failed. ----\n", __func__, __LINE__);
            return 0;
        }

        for (int i = 0; i < MAX_INPUT_DEVICE_COUNT; i++) {
            if (mountDevIndex_[i].devIndex != 0) {
                devcount = devcount + 1;
            }
        }
    }
    int jectcount = 0;
    if (injectInterface_ != nullptr || injectInterface_->iInputManager != nullptr) {
        int32_t ret = injectInterface_->iInputManager->ScanInputDevice(&mountDevIndex_[devcount],
                                                                       MAX_INPUT_DEVICE_COUNT);
        if (ret) {
            MMI_LOGE("---- %{public}s:%{public}d Error:injectInterface_ ScanInputDevice failed. ----\n",
                __func__, __LINE__);
            return devcount;
        }

        for (int i = 0; i < MAX_INPUT_DEVICE_COUNT; i++) {
            if (mountDevIndex_[devcount + i].devIndex != 0) {
                jectcount = jectcount + 1;
            }
        }
    }
    return devcount + jectcount;
}
void OHOS::MMI::HdfEventManager::SetupCallback()
{
    MMI_LOGD("---- %{public}s:%{public}d ThreadSetupCallback start ! ----\n", __func__, __LINE__);
    uint32_t ret = GetInputInterface(&inputInterface_);
    if (ret != 0 || inputInterface_ == nullptr
        || inputInterface_->iInputManager == nullptr
        || inputInterface_->iInputReporter == nullptr) {
        MMI_LOGD("---- %{public}s:%{public}d inputInterface_ init fail! ----\n", __func__, __LINE__);
    }

    ret = GetInputInterfaceFromInject(&injectInterface_);
    if (ret != 0 || injectInterface_ == nullptr
        || injectInterface_->iInputManager == nullptr
        || injectInterface_->iInputReporter == nullptr) {
        MMI_LOGD("---- %{public}s:%{public}d injectInterface_ init fail! ----\n", __func__, __LINE__);
    }

    eventcallback.EventPkgCallback = m_globleThis->GetEventCallback;
    hostplugcallback.HotPlugCallback = m_globleThis->HotPlugCallback;
    if (inputInterface_) {
        ret = inputInterface_->iInputReporter->RegisterHotPlugCallback(&hostplugcallback);
        if (ret == INPUT_SUCCESS) {
            MMI_LOGI("---- %{public}s:%{public}d RegisterHotPlugCallback INPUT_SUCCESS  \n", __func__, __LINE__);
        } else {
            MMI_LOGE("---- %{public}s:%{public}d RegisterHotPlugCallback INPUT_ERROR \n", __func__, __LINE__);
        }
    }

    if (injectInterface_) {
        ret = injectInterface_->iInputReporter->RegisterHotPlugCallback(&hostplugcallback);
        if (ret == INPUT_SUCCESS) {
            MMI_LOGI("---- %{public}s:%{public}d injectInterface_ RegisterHotPlugCallback INPUT_SUCCESS  \n",
                __func__, __LINE__);
        } else {
            MMI_LOGE("---- %{public}s:%{public}d injectInterface_ RegisterHotPlugCallback INPUT_ERROR \n",
                __func__, __LINE__);
        }
    }

    int count = GetDeviceCount();
    MMI_LOGD("----  ThreadSetupCallback count = %{public}d! ----\n",  count);
    for (int i = 0; i < count; i++) {
        DeviceAddHandle(mountDevIndex_[i].devIndex, mountDevIndex_[i].devType);
    }
}

void OHOS::MMI::HdfEventManager::AddDevice(uint32_t devIndex, uint32_t devType)
{
    uint32_t ret = 0;
    if (devIndex >= MAX_INPUT_DEVICE_COUNT) {
        ret = injectInterface_->iInputReporter->RegisterReportCallback(devIndex, &eventcallback);
        return;
    }
    if (!OpenHdfDevice(devIndex, true)) {
        return;
    }
    ret = inputInterface_->iInputReporter->RegisterReportCallback(devIndex, &eventcallback);
    if (ret == INPUT_SUCCESS) {
        MMI_LOGI("---- %{public}s:%{public}d RegisterReportCallback eventcallback INPUT_SUCCESS "
            "devindex=%{public}u--  devType=%{public}u-- \n", __func__, __LINE__, devIndex, devType);
    } else {
        MMI_LOGE("---- %{public}s:%{public}d RegisterReportCallback eventcallback INPUT_ERROR "
            "devindex=%{public}u -- devType=%{public}u-- \n", __func__, __LINE__, devIndex, devType);
    }
}
bool OHOS::MMI::HdfEventManager::OpenHdfDevice(uint32_t devIndex, bool oper)
{
    int32_t ret = -1;
    if (devIndex >= MAX_INPUT_DEVICE_COUNT) {
        return true;
    }
    if (oper) {
        ret = inputInterface_->iInputManager->OpenInputDevice(devIndex);
    } else {
        ret = inputInterface_->iInputManager->CloseInputDevice(devIndex);
    }
    if (ret == 0) {
        MMI_LOGI("---- %{public}s:%{public}d Info: device success! ----\n", __func__, __LINE__);
        return true;
    }

    if (ret != 0) {
        MMI_LOGE("---- %{public}s:%{public}d Error: device fail! code=%{public}u----\n", __func__, __LINE__, ret);
    }
    return false;
}
void OHOS::MMI::HdfEventManager::HotPlugCallback(const HotPlugEvent *event)
{
    MMI_LOGD("---- %{public}s:%{public}d HotPlugCallback status=%{public}u devindex=%{public}u--  "
        "devType=%{public}u-- \n", __func__, __LINE__, event->status, event->devIndex, event->devType);

    if (!event->status) {
        DeviceAddHandle(event->devIndex, event->devType);
    } else {
        DeviceRemoveHandle(event->devIndex, event->devType);
    }
}
int OHOS::MMI::HdfEventManager::DeviceRemoveHandle(uint32_t devIndex, uint32_t devType)
{
    MMI_LOGD("---- %{public}s:%{public}d DeviceRemoveHandle devindex=%{public}u--  devType=%{public}u-- \n",
        __func__, __LINE__, devIndex, devType);
    Devcmd cmd;
    cmd.index = devIndex;
    cmd.cmd = (int)HDF_RMV_DEVICE;
    libinput_devpipe_write(m_globleThis->hdiinput_, &cmd, sizeof(Devcmd));
    if (devIndex < MAX_INPUT_DEVICE_COUNT) {
        uint32_t ret = m_globleThis->inputInterface_->iInputReporter->UnregisterReportCallback(devIndex);
        if (ret == INPUT_SUCCESS) {
            MMI_LOGI("---- %{public}s:%{public}d REMOVE_SUCCESS devindex=%{public}u--  devType=%{public}u-- \n",
                __func__, __LINE__, devIndex, devType);
        } else {
            MMI_LOGE("---- %{public}s:%{public}d REMOVE_ERROR devindex=%{public}u -- devType=%{public}u-- \n",
                __func__, __LINE__, devIndex, devType);
        }
    }
    m_globleThis->OpenHdfDevice(devIndex, false);
    return RET_OK;
}


void OHOS::MMI::HdfEventManager::GetEventCallback(const EventPackage **pkgs, uint32_t count, uint32_t devIndex)
{
    const uint16_t byteSize = 8;
    if (pkgs == nullptr) {
        MMI_LOGE("---- %{public}s:%{public}d Error:pkgs is nullptr.----\n", __func__, __LINE__);
        return;
    }
    input_event eventarry[MAX_EVENT_PKG_NUM];
    for (uint32_t i = 0; i < count && i < MAX_EVENT_PKG_NUM; i++) {
        eventarry[i].code = pkgs[i]->code;
        eventarry[i].type = (pkgs[i]->type) | (uint16_t)(devIndex<<byteSize);     // 不改变livinput结构传递，对象的index参数
        eventarry[i].value = pkgs[i]->value;
        eventarry[i].input_event_sec = (pkgs[i]->timestamp) / (USEC_PER_SEC);
        eventarry[i].input_event_usec = (pkgs[i]->timestamp) % (USEC_PER_SEC);
    }
    if (!m_globleThis->devStatus[devIndex]) {
        return;
    }
    libinput_pipe_write(m_globleThis->hdiinput_, devIndex, eventarry, count * sizeof(input_event));
}
int OHOS::MMI::HdfEventManager::DeviceAddHandle(uint32_t devIndex, uint32_t devType)
{
    MMI_LOGD("---- %{public}s:%{public}d DeviceAddHandle devindex=%{public}u--  devType=%{public}u-- \n",
        __func__, __LINE__, devIndex, devType);
    m_globleThis->devStatus[devIndex] = false;
    uhdf *hdiuhdf = nullptr;
    hdiuhdf = new(uhdf);
    hdiuhdf->index = devIndex;
    hdiuhdf->type = m_globleThis->HdfdevtypeMapLibinputType(devIndex, devType);
    hdiuhdf->nproperties = 0;
    hdiuhdf->quirkpop = nullptr;
    hdiuhdf->modeltype = 0;
    hdiuhdf->fn = (hdiuhdf->index >= MAX_INPUT_DEV_NUM) ? EvdevSimIoctl : EvdevIoctl;
    m_globleThis->hdflist_.push_back(hdiuhdf);
    Devcmd cmd;
    cmd.index = devIndex;
    cmd.cmd = (int)HDF_ADD_DEVICE;
    libinput_devpipe_write(m_globleThis->hdiinput_, &cmd, sizeof(Devcmd));
    return RET_OK;
}
const struct libinput_interface _hdfinterface = {
    .open_restricted = [](const char *path, int flags, void *user_data)->int {
        int fd = -1;
        MMI_LOGD("libinput .open_restricted path:%{public}s fd:%{public}d", path, fd);
        return fd < 0 ? -errno : fd;
    },
    .close_restricted = [](int fd, void *user_data)
    {
        MMI_LOGD("libinput .close_restricted fd:%{public}d", fd);
    },
};
libinput *OHOS::MMI::HdfEventManager::HdfLibinputInit()
{
    if (m_globleThis->hdiinput_ == nullptr) {
        m_globleThis->hdiinput_ = libinput_hdf_create_context(&_hdfinterface, nullptr);
    }
    MMI_LOGD("HdfLibinputInit function end\n");
    return m_globleThis->hdiinput_;
}
int OHOS::MMI::HdfEventManager::HdfDevHandle(int index, hdf_event_type cmd)
{
    if (cmd != HDF_ADD_DEVICE) {
        MMI_LOGD("HdfRmv function start\n");
        uhdf *hdiuhdf = nullptr;
        for (std::list<uhdf*>::iterator it = m_globleThis->hdflist_.begin();
             it != m_globleThis->hdflist_.end(); ++it) {
            uhdf *hdiuhdfit = *it;
            if (hdiuhdfit->index == (int)index) {
                hdiuhdf = *it;
                m_globleThis->hdflist_.remove(*it);
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
    for (std::list<uhdf*>::iterator it = m_globleThis->hdflist_.begin();
        it != m_globleThis->hdflist_.end(); ++it) {
        uhdf *hdiuhdfit = *it;
        if (hdiuhdfit->index != (int)index) {
            continue;
        }

        hdiuhdf = *it;
        DeviceInfo *deviceinfo = nullptr;
        m_globleThis->AddDevice(index, hdiuhdf->type);
        if (index < MAX_INPUT_DEVICE_COUNT) {
            uint32_t ret = m_globleThis->inputInterface_->iInputManager->GetInputDevice(index, &deviceinfo);
            if (ret != 0 || (deviceinfo == nullptr)) {
                MMI_LOGE("---- %{public}s:%{public}d inputInterface_ GetInputDevice ret =%{public}d \n", __func__, __LINE__, ret);
                return RET_ERR;
            }
            hdiuhdf->deviceinfo = (void*)deviceinfo;
        }
        uhdfdevice_added(m_globleThis->hdiinput_, hdiuhdf, "default");
        m_globleThis->devStatus[index] = true;
        return RET_OK;
    }
    return RET_OK;
}
bool OHOS::MMI::HdfEventManager::Init()
{
    return true;
}
OHOS::MMI::HdfEventManager  hdfEventManager;
extern "C" libinput *HdfAdfInit()
{
    MMI_LOGD("HdfAdfInit function start\n");
    return hdfEventManager.HdfLibinputInit();
}

extern "C" int HdfDevHandle(int index, OHOS::MMI::hdf_event_type cmd)
{
    MMI_LOGD("HdfDevHandle function start index = %{public}d, cmd =%{public}d\n", index, cmd);
    return hdfEventManager.HdfDevHandle(index, cmd);
}
#endif