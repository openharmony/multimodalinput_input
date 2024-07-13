/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "device_manager.h"

#include <algorithm>
#include <cstring>
#include <regex>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/stat.h>

#ifdef OHOS_BUILD_ENABLE_COORDINATION
#include "coordination_util.h"
#endif // OHOS_BUILD_ENABLE_COORDINATION
#include "device.h"
#include "devicestatus_define.h"
#include "fi_log.h"
#include "napi_constants.h"

#undef LOG_TAG
#define LOG_TAG "DeviceManager"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace {
constexpr size_t EXPECTED_N_SUBMATCHES { 2 };
constexpr size_t EXPECTED_SUBMATCH { 1 };
const std::string FINGER_PRINT { "hw_fingerprint_mouse" };
} // namespace

DeviceManager::HotplugHandler::HotplugHandler(DeviceManager &devMgr)
    : devMgr_(devMgr)
{}

void DeviceManager::HotplugHandler::AddDevice(const std::string &devNode)
{
    devMgr_.AddDevice(devNode);
}

void DeviceManager::HotplugHandler::RemoveDevice(const std::string &devNode)
{
    devMgr_.RemoveDevice(devNode);
}

DeviceManager::DeviceManager()
    : hotplug_(*this)
{}

int32_t DeviceManager::Init(IContext *context)
{
    CALL_INFO_TRACE;
    CHKPR(context, RET_ERR);
    int32_t ret = context->GetDelegateTasks().PostSyncTask([this, context] {
        return this->OnInit(context);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post sync task failed");
    }
    return ret;
}

int32_t DeviceManager::OnInit(IContext *context)
{
    CALL_INFO_TRACE;
    CHKPR(context, RET_ERR);
    context_ = context;
    monitor_.SetDeviceMgr(&hotplug_);
    enumerator_.SetDeviceMgr(&hotplug_);
    return RET_OK;
}

int32_t DeviceManager::Enable()
{
    CALL_INFO_TRACE;
    CHKPR(context_, RET_ERR);
    int32_t ret = context_->GetDelegateTasks().PostSyncTask([this] {
        return this->OnEnable();
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post sync task failed");
    }
    return ret;
}

int32_t DeviceManager::OnEnable()
{
    CALL_DEBUG_ENTER;
    epollMgr_ = std::make_shared<EpollManager>();
    int32_t ret = epollMgr_->Open();
    if (ret != RET_OK) {
        return ret;
    }
    ret = monitor_.Enable();
    if (ret != RET_OK) {
        goto CLOSE_EPOLL;
    }
    ret = epollMgr_->Add(monitor_);
    if (ret != RET_OK) {
        goto DISABLE_MONITOR;
    }
    enumerator_.ScanDevices();
    return RET_OK;

DISABLE_MONITOR:
    monitor_.Disable();

CLOSE_EPOLL:
    epollMgr_.reset();
    return ret;
}

int32_t DeviceManager::Disable()
{
    CALL_INFO_TRACE;
    CHKPR(context_, RET_ERR);
    int32_t ret = context_->GetDelegateTasks().PostSyncTask([this] {
        return this->OnDisable();
    });
    if (ret != RET_OK) {
        FI_HILOGE("PostSyncTask failed");
    }
    return ret;
}

int32_t DeviceManager::OnDisable()
{
    CHKPR(epollMgr_, RET_ERR);
    epollMgr_->Remove(monitor_);
    monitor_.Disable();
    epollMgr_.reset();
    return RET_OK;
}

std::shared_ptr<IDevice> DeviceManager::FindDevice(const std::string &devPath)
{
    auto tIter = std::find_if(devices_.cbegin(), devices_.cend(),
        [devPath](const auto &item) {
            return ((item.second != nullptr) && (item.second->GetDevPath() == devPath));
        });
    return (tIter != devices_.cend() ? tIter->second : nullptr);
}

int32_t DeviceManager::ParseDeviceId(const std::string &devNode)
{
    CALL_DEBUG_ENTER;
    std::regex pattern("^event(\\d+)$");
    std::smatch mr;

    if (std::regex_match(devNode, mr, pattern)) {
        if (mr.ready() && mr.size() == EXPECTED_N_SUBMATCHES) {
            return std::stoi(mr[EXPECTED_SUBMATCH].str());
        }
    }
    return RET_ERR;
}

std::shared_ptr<IDevice> DeviceManager::AddDevice(const std::string &devNode)
{
    CALL_INFO_TRACE;
    const std::string SYS_INPUT_PATH { "/sys/class/input/" };
    const std::string devPath { DEV_INPUT_PATH + devNode };
    struct stat statbuf;

    if (stat(devPath.c_str(), &statbuf) != 0) {
        FI_HILOGD("Invalid device path:%{public}s", devPath.c_str());
        return nullptr;
    }
    if (!S_ISCHR(statbuf.st_mode)) {
        FI_HILOGD("Not character device:%{public}s", devPath.c_str());
        return nullptr;
    }

    int32_t deviceId = ParseDeviceId(devNode);
    if (deviceId < 0) {
        FI_HILOGE("Parsing device name failed:%{public}s", devNode.c_str());
        return nullptr;
    }

    std::shared_ptr<IDevice> dev = FindDevice(devPath);
    if (dev != nullptr) {
        FI_HILOGD("Already exists:%{public}s", devPath.c_str());
        return dev;
    }

    const std::string lSysPath { SYS_INPUT_PATH + devNode };
    char rpath[PATH_MAX];
    if (realpath(lSysPath.c_str(), rpath) == nullptr) {
        FI_HILOGD("Invalid sysPath:%{public}s", lSysPath.c_str());
        return nullptr;
    }

    dev = std::make_shared<Device>(deviceId);
    dev->SetDevPath(devPath);
    dev->SetSysPath(std::string(rpath));
    if (dev->Open() != RET_OK) {
        FI_HILOGE("Unable to open \'%{public}s\'", devPath.c_str());
        return nullptr;
    }
    auto ret = devices_.insert_or_assign(dev->GetId(), dev);
    if (ret.second) {
        FI_HILOGD("\'%{public}s\' added", dev->GetName().c_str());
        OnDeviceAdded(dev);
    }
    return dev;
}

std::shared_ptr<IDevice> DeviceManager::RemoveDevice(const std::string &devNode)
{
    CALL_INFO_TRACE;
    const std::string devPath { DEV_INPUT_PATH + devNode };

    for (auto devIter = devices_.begin(); devIter != devices_.end(); ++devIter) {
        std::shared_ptr<IDevice> dev = devIter->second;
        CHKPC(dev);
        if (dev->GetDevPath() == devPath) {
            devices_.erase(devIter);
            FI_HILOGD("\'%{public}s\' removed", dev->GetName().c_str());
            dev->Close();
            OnDeviceRemoved(dev);
            return dev;
        }
    }
    FI_HILOGD("\'%{public}s\' was not found", devNode.c_str());
    return nullptr;
}

void DeviceManager::OnDeviceAdded(std::shared_ptr<IDevice> dev)
{
    CHKPV(dev);
    FI_HILOGI("Add device %{public}d:%{public}s", dev->GetId(), dev->GetDevPath().c_str());
    FI_HILOGI("  sysPath:       \"%{public}s\"", dev->GetSysPath().c_str());
    FI_HILOGI("  bus:           %{public}04x", dev->GetBus());
    FI_HILOGI("  vendor:        %{public}04x", dev->GetVendor());
    FI_HILOGI("  product:       %{public}04x", dev->GetProduct());
    FI_HILOGI("  version:       %{public}04x", dev->GetVersion());
    FI_HILOGI("  name:          \"%{public}s\"", dev->GetName().c_str());
    FI_HILOGI("  location:      \"%{public}s\"", dev->GetPhys().c_str());
    FI_HILOGI("  unique id:     \"%{public}s\"", dev->GetUniq().c_str());
    FI_HILOGI("  is pointer:    %{public}s, is keyboard:%{public}s",
        dev->IsPointerDevice() ? "True" : "False", dev->IsKeyboard() ? "True" : "False");

    for (const auto &observer : observers_) {
        std::shared_ptr<IDeviceObserver> ptr = observer.lock();
        CHKPC(ptr);
        ptr->OnDeviceAdded(dev);
    }
}

void DeviceManager::OnDeviceRemoved(std::shared_ptr<IDevice> dev)
{
    for (const auto &observer : observers_) {
        std::shared_ptr<IDeviceObserver> ptr = observer.lock();
        CHKPC(ptr);
        ptr->OnDeviceRemoved(dev);
    }
}

void DeviceManager::Dispatch(const struct epoll_event &ev)
{
    CALL_DEBUG_ENTER;
    CHKPV(context_);
    int32_t ret = context_->GetDelegateTasks().PostAsyncTask([this, &ev] {
        return this->OnEpollDispatch(ev.events);
    });
    if (ret != RET_OK) {
        FI_HILOGE("PostAsyncTask failed");
    }
}

int32_t DeviceManager::OnEpollDispatch(uint32_t events)
{
    struct epoll_event ev {};
    ev.events = events;
    ev.data.ptr = epollMgr_.get();

    CHKPR(epollMgr_, RET_ERR);
    epollMgr_->Dispatch(ev);
    return RET_OK;
}

std::shared_ptr<IDevice> DeviceManager::GetDevice(int32_t id) const
{
    CHKPP(context_);
    std::packaged_task<std::shared_ptr<IDevice>(int32_t)> task {[this](int32_t id) {
        return this->OnGetDevice(id);
    }};
    auto fu = task.get_future();

    int32_t ret = context_->GetDelegateTasks().PostSyncTask([this, &task, id] {
        return this->RunGetDevice(std::ref(task), id);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post task failed");
        return nullptr;
    }
    return fu.get();
}

std::shared_ptr<IDevice> DeviceManager::OnGetDevice(int32_t id) const
{
    if (auto devIter = devices_.find(id); devIter != devices_.cend()) {
        return devIter->second;
    }
    FI_HILOGE("Device id not found");
    return nullptr;
}

int32_t DeviceManager::RunGetDevice(std::packaged_task<std::shared_ptr<IDevice>(int32_t)> &task,
                                    int32_t id) const
{
    task(id);
    return RET_OK;
}

void DeviceManager::RetriggerHotplug(std::weak_ptr<IDeviceObserver> observer)
{
    CALL_INFO_TRACE;
    CHKPV(context_);
    int32_t ret = context_->GetDelegateTasks().PostSyncTask([this, observer] {
        return this->OnRetriggerHotplug(observer);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post task failed");
    }
}

int32_t DeviceManager::OnRetriggerHotplug(std::weak_ptr<IDeviceObserver> observer)
{
    CALL_INFO_TRACE;
    CHKPR(observer, RET_ERR);
    std::shared_ptr<IDeviceObserver> ptr = observer.lock();
    CHKPR(ptr, RET_ERR);
    std::for_each(devices_.cbegin(), devices_.cend(),
        [ptr] (const auto &item) {
            if (item.second != nullptr) {
                ptr->OnDeviceAdded(item.second);
            }
        });
    return RET_OK;
}

int32_t DeviceManager::AddDeviceObserver(std::weak_ptr<IDeviceObserver> observer)
{
    CALL_DEBUG_ENTER;
    CHKPR(context_, RET_ERR);
    int32_t ret = context_->GetDelegateTasks().PostSyncTask([this, observer] {
        return this->OnAddDeviceObserver(observer);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post task failed");
    }
    return ret;
}

int32_t DeviceManager::OnAddDeviceObserver(std::weak_ptr<IDeviceObserver> observer)
{
    CALL_INFO_TRACE;
    CHKPR(observer, RET_ERR);
    auto ret = observers_.insert(observer);
    if (!ret.second) {
        FI_HILOGW("Observer is duplicated");
    }
    return RET_OK;
}

void DeviceManager::RemoveDeviceObserver(std::weak_ptr<IDeviceObserver> observer)
{
    CALL_INFO_TRACE;
    CHKPV(context_);
    int32_t ret = context_->GetDelegateTasks().PostSyncTask([this, observer] {
        return this->OnRemoveDeviceObserver(observer);
    });
    if (ret != RET_OK) {
        FI_HILOGE("Post task failed");
    }
}

int32_t DeviceManager::OnRemoveDeviceObserver(std::weak_ptr<IDeviceObserver> observer)
{
    CALL_INFO_TRACE;
    CHKPR(observer, RET_ERR);
    observers_.erase(observer);
    return RET_OK;
}

bool DeviceManager::AnyOf(std::function<bool(std::shared_ptr<IDevice>)> pred)
{
    return std::any_of(devices_.cbegin(), devices_.cend(), [pred](const auto &item) {
        return (pred != nullptr ? pred(item.second) : false);
    });
}

bool DeviceManager::HasLocalPointerDevice()
{
    return AnyOf([this](std::shared_ptr<IDevice> dev) {
        if ((dev == nullptr) || (dev->GetName() == FINGER_PRINT)) {
            return false;
        }
        return (dev->IsPointerDevice() && !dev->IsRemote());
    });
}

bool DeviceManager::HasLocalKeyboardDevice()
{
    return AnyOf([this](std::shared_ptr<IDevice> dev) {
        CHKPR(dev, false);
        return (dev->IsKeyboard() && !dev->IsRemote());
    });
}

bool DeviceManager::HasKeyboard()
{
    return AnyOf([this](std::shared_ptr<IDevice> dev) {
        if ((dev == nullptr)) {
            return false;
        }
        return (dev->IsKeyboard() && !dev->IsRemote() &&
            dev->GetKeyboardType() == IDevice::KeyboardType::KEYBOARD_TYPE_ALPHABETICKEYBOARD);
    });
}

std::vector<std::shared_ptr<IDevice>> DeviceManager::GetKeyboard()
{
    std::vector<std::shared_ptr<IDevice>> keyboards;
    for (const auto &dev : devices_) {
        if (dev.second->IsKeyboard() && !dev.second->IsRemote() &&
            dev.second->GetKeyboardType() == IDevice::KeyboardType::KEYBOARD_TYPE_ALPHABETICKEYBOARD) {
            keyboards.push_back(dev.second);
        }
    }
    return keyboards;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS