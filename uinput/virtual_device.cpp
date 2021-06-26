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

#include "virtual_device.h"

#include <cerrno>
#include <cinttypes>
#include <cstring>

#include <fcntl.h>
#include <securec.h>
#include <unistd.h>

#include "hilog/log.h"

namespace {
using namespace OHOS::HiviewDFX;
constexpr HiLogLabel LABEL = { LOG_CORE, 0xD002800, "VirtualDevice" };
}
bool DoIoctl(int32_t fd, int32_t request, const uint32_t value)
{
    int32_t rc = ioctl(fd, request, value);
    if (rc < 0) {
        HiLog::Error(LABEL, "%{public}s ioctl failed", __func__);
        return false;
    }
    return true;
}

VirtualDevice::VirtualDevice(const char *deviceName, uint16_t productId)
    : deviceName_(deviceName),
      busType_(BUS_USB),
      vendorId_(0x6006),
      productId_(productId),
      version_(1) {}  // The version number is one.

VirtualDevice::~VirtualDevice()
{
    if (fd_ >= 0) {
        ioctl(fd_, UI_DEV_DESTROY);
        close(fd_);
        fd_ = -1;
    }
}

bool VirtualDevice::SetUp()
{
    fd_ = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd_ < 0) {
        HiLog::Error(LABEL, "Failed to open uinput %{public}s", __func__);
        return false;
    }

    errno_t ret = strncpy_s(dev_.name, MAX_NAME_LENGTH, deviceName_, sizeof(dev_.name));
    if (ret != EOK) {
        HiLog::Error(LABEL, "%{public}s, failed to copy deviceName", __func__);
        return false;
    }

    dev_.id.bustype = busType_;
    dev_.id.vendor = vendorId_;
    dev_.id.product = productId_;
    dev_.id.version = version_;
    for (uint32_t evt_type : GetEventTypes()) {
        if (!DoIoctl(fd_, UI_SET_EVBIT, evt_type)) {
            HiLog::Error(LABEL, "%{public}s Error setting event type: %{public}u", __func__, evt_type);
            return false;
        }
    }

    for (uint32_t key : GetKeys()) {
        if (!DoIoctl(fd_, UI_SET_KEYBIT, key)) {
            HiLog::Error(LABEL, "%{public}s Error setting key: %{public}u", __func__, key);
            return false;
        }
    }

    for (uint32_t property : GetProperties()) {
        if (!DoIoctl(fd_, UI_SET_PROPBIT, property)) {
            HiLog::Error(LABEL, "%{public}s Error setting property: %{public}u", __func__, property);
            return false;
        }
    }

    for (uint32_t abs : GetAbs()) {
        if (!DoIoctl(fd_, UI_SET_ABSBIT, abs)) {
            HiLog::Error(LABEL, "%{public}s Error setting property: %{public}u", __func__, abs);
            return false;
        }
    }

    for (uint32_t rel : GetRelBits()) {
        if (!DoIoctl(fd_, UI_SET_RELBIT, rel)) {
            HiLog::Error(LABEL, "%{public}s Error setting rel: %{public}u", __func__, rel);
            return false;
        }
    }

    if (write(fd_, &dev_, sizeof(dev_)) < 0) {
        HiLog::Error(LABEL, "Unable to set input device info: %{public}s", __func__);
        return false;
    }
    if (ioctl(fd_, UI_DEV_CREATE) < 0) {
        HiLog::Error(LABEL, "Unable to create input device : %{public}s", __func__);
        return false;
    }
    return true;
}

bool VirtualDevice::EmitEvent(uint16_t type, uint16_t code, uint32_t value) const
{
    struct input_event event {};
    event.type = type;
    event.code = code;
    event.value = value;
#ifndef __MUSL__
    gettimeofday(&event.time, NULL);
#endif
    if (write(fd_, &event, sizeof(event)) < static_cast<ssize_t>(sizeof(event))) {
        HiLog::Error(LABEL, "Event write failed %{public}s aborting", __func__);
        return false;
    }
    return true;
}

const std::vector<uint32_t> &VirtualDevice::GetEventTypes() const
{
    static const std::vector<uint32_t> evtTypes {};
    return evtTypes;
}

const std::vector<uint32_t> &VirtualDevice::GetKeys() const
{
    static const std::vector<uint32_t> keys {};
    return keys;
}

const std::vector<uint32_t> &VirtualDevice::GetProperties() const
{
    static const std::vector<uint32_t> properties {};
    return properties;
}

const std::vector<uint32_t> &VirtualDevice::GetAbs() const
{
    static const std::vector<uint32_t> abs {};
    return abs;
}

const std::vector<uint32_t> &VirtualDevice::GetRelBits() const
{
    static const std::vector<uint32_t> relBits {};
    return relBits;
}
