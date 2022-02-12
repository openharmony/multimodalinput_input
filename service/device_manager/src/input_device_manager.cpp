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

#include "input_device_manager.h"
#include "pointer_drawing_manager.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "InputDeviceManager"};
    constexpr int32_t INVALID_DEVICE_ID {-1};
}
#ifdef OHOS_WESTEN_MODEL
void InputDeviceManager::Init(weston_compositor* wc)
{
    MMI_LOGD("begin");
    if (initFlag_) {
        return;
    }
    constexpr int32_t size = 32;
    void* devices[size] = {0};
    weston_get_device_info(wc, size, devices);
    for (int32_t i = 0; i < size; i++) {
        libinput_device* item = static_cast<libinput_device*>(devices[i]);
        if (item == NULL) {
            continue;
        }
        inputDevice_.insert(std::pair<int32_t, libinput_device*>(nextId_,
            static_cast<struct libinput_device*>(devices[i])));
        nextId_++;
    }
    initFlag_ = true;
    MMI_LOGD("end");
}

void InputDeviceManager::GetInputDeviceIdsAsync(std::function<void(std::vector<int32_t>)> callback)
{
    MMIMsgPost.RunOnWestonThread([this, callback](weston_compositor* wc) {
        auto ids = GetInputDeviceIdsSync(wc);
        callback(ids);
    });
}

void InputDeviceManager::FindInputDeviceByIdAsync(int32_t deviceId,
    std::function<void(std::shared_ptr<InputDevice>)> callback)
{
    MMIMsgPost.RunOnWestonThread([this, deviceId, callback](weston_compositor* wc) {
        auto device = FindInputDeviceByIdSync(wc, deviceId);
        callback(device);
    });
}

std::vector<int32_t> InputDeviceManager::GetInputDeviceIdsSync(weston_compositor* wc)
{
    MMI_LOGD("begin");
    Init(wc);
    std::vector<int32_t> ids;
    for (const auto& item : inputDevice_) {
        ids.push_back(item.first);
    }
    MMI_LOGD("end");
    return ids;
}

std::shared_ptr<InputDevice> InputDeviceManager::FindInputDeviceByIdSync(weston_compositor* wc, int32_t deviceId)
{
    MMI_LOGD("begin");
    Init(wc);
    auto item = inputDevice_.find(deviceId);
    if (item == inputDevice_.end()) {
        MMI_LOGE("failed to search for the device");
        return nullptr;
    }

    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    inputDevice->SetId(item->first);
    int32_t deviceType = static_cast<int32_t>(libinput_device_get_tags(
        static_cast<libinput_device *>(item->second)));
    inputDevice->SetType(deviceType);
    std::string name = libinput_device_get_name(static_cast<libinput_device *>(item->second));
    inputDevice->SetName(name);
    MMI_LOGD("end");
    return inputDevice;
}
#endif

std::shared_ptr<InputDevice> InputDeviceManager::GetInputDevice(int32_t id)
{
    MMI_LOGD("begin");
    auto item = inputDevice_.find(id);
    if (item == inputDevice_.end()) {
        MMI_LOGE("failed to search for the device");
        return nullptr;
    }

    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    if (inputDevice == nullptr) {
        MMI_LOGE("create InputDevice ptr failed");
        return nullptr;
    }
    inputDevice->SetId(item->first);
    int32_t deviceType = static_cast<int32_t>(libinput_device_get_tags(item->second));
    inputDevice->SetType(deviceType);
    std::string name = libinput_device_get_name(item->second);
    inputDevice->SetName(name);
    MMI_LOGD("end");
    return inputDevice;
}

std::vector<int32_t> InputDeviceManager::GetInputDeviceIds()
{
    MMI_LOGD("begin");
    std::vector<int32_t> ids;
    for (const auto &item : inputDevice_) {
        ids.push_back(item.first);
    }
    MMI_LOGD("end");
    return ids;
}

void InputDeviceManager::OnInputDeviceAdded(libinput_device* inputDevice)
{
    MMI_LOGD("begin");
    CHKP(inputDevice);
#ifdef OHOS_WESTEN_MODEL
    if (initFlag_) {
        return;
    }
#endif
    for (const auto& item : inputDevice_) {
        if (item.second == inputDevice) {
            MMI_LOGI("the device already exists");
            return;
        }
    }
    if (nextId_ == INT32_MAX) {
        MMI_LOGE("the nextId_ exceeded the upper limit");
        return;
    }
    inputDevice_[nextId_] = inputDevice;
    ++nextId_;

    if (IsPointerDevice(inputDevice)) {
        DrawWgr->TellDeviceInfo(true);
    }
    MMI_LOGD("end");
}

void InputDeviceManager::OnInputDeviceRemoved(libinput_device* inputDevice)
{
    MMI_LOGD("begin");
    CHKP(inputDevice);
#ifdef OHOS_WESTEN_MODEL
    if (initFlag_) {
        return;
    }
#endif
    for (auto it = inputDevice_.begin(); it != inputDevice_.end(); ++it) {
        if (it->second == inputDevice) {
            inputDevice_.erase(it);
            if (IsPointerDevice(inputDevice)) {
                DrawWgr->TellDeviceInfo(false);
            }
            break;
        }
    }
    MMI_LOGD("end");
}

bool InputDeviceManager::IsPointerDevice(libinput_device* device)
{
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    MMI_LOGD("udev tag is%{public}d", static_cast<int32_t>(udevTags));
    return udevTags & (EVDEV_UDEV_TAG_MOUSE | EVDEV_UDEV_TAG_TRACKBALL | EVDEV_UDEV_TAG_POINTINGSTICK | 
    EVDEV_UDEV_TAG_TOUCHPAD | EVDEV_UDEV_TAG_TABLET_PAD);
}

int32_t InputDeviceManager::FindInputDeviceId(libinput_device* inputDevice)
{
    MMI_LOGD("begin");
    CHKPR(inputDevice, INVALID_DEVICE_ID);
    for (const auto& item : inputDevice_) {
        if (item.second == inputDevice) {
            MMI_LOGI("find input device id success");
            return item.first;
        }
    }
    MMI_LOGI("find input device id failed");
    MMI_LOGD("end");
    return INVALID_DEVICE_ID;
}
} // namespace MMI
} // namespace OHOS
