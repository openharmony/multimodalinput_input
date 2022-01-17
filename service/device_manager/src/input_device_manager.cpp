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
}
#ifdef OHOS_WESTEN_MODEL
void InputDeviceManager::Init(weston_compositor* wc)
{
    if (initFlag_) {
        return;
    }
    //constexpr int32_t size = 32;
    //void* devices[size] = {0};
    // weston_get_device_info(wc, size, devices);
    // for (int32_t i = 0; i < size; i++) {
    //     struct libinput_device* item = static_cast<struct libinput_device*>(devices[i]);
    //     if (item == NULL) {
    //         continue;
    //     }
    //     inputDeviceMap_.insert(std::pair<int32_t, libinput_device*>(nextId_,
    //         static_cast<struct libinput_device*>(devices[i])));
    //     nextId_++;
    // }
    initFlag_ = true;
}

void InputDeviceManager::GetDeviceIdListAsync(std::function<void(std::vector<int32_t>)> callback)
{
    MMIMSGPOST.RunOnWestonThread([this, callback](weston_compositor* wc) {
        auto idList = GetDeviceIdListSync(wc);
        callback(idList);
    });
}

void InputDeviceManager::FindDeviceByIdAsync(int32_t deviceId,
    std::function<void(std::shared_ptr<InputDevice>)> callback)
{
    MMIMSGPOST.RunOnWestonThread([this, deviceId, callback](weston_compositor* wc) {
        auto device = FindDeviceByIdSync(wc, deviceId);
        callback(device);
    });
}

std::vector<int32_t> InputDeviceManager::GetDeviceIdListSync(weston_compositor* wc)
{
    MMI_LOGI("GetDeviceIdList enter");
    Init(wc);
    std::vector<int32_t> deviceIdList;
    for (auto it : inputDeviceMap_) {
        deviceIdList.push_back(it.first);
    }
    return deviceIdList;
}

std::shared_ptr<InputDevice> InputDeviceManager::FindDeviceByIdSync(weston_compositor* wc, int32_t deviceId)
{
    MMI_LOGI("FindDeviceByIdSync enter");
    Init(wc);
    auto item = inputDeviceMap_.find(deviceId);
    if (item == inputDeviceMap_.end()) {
        return nullptr;
    }

    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    inputDevice->SetId(item->first);
    int32_t deviceType = static_cast<int32_t>(libinput_device_get_tags(
        static_cast<struct libinput_device *>(item->second)));
    inputDevice->SetDeviceType(deviceType);
    std::string name = libinput_device_get_name(static_cast<struct libinput_device *>(item->second));
    inputDevice->SetName(name);

    return inputDevice;
}
#endif

std::shared_ptr<InputDevice> InputDeviceManager::GetDevice(int32_t id)
{
    MMI_LOGI("FindDeviceById enter");
    auto item = inputDeviceMap_.find(id);
    if (item == inputDeviceMap_.end()) {
        MMI_LOGE("find device by id failed");
        return nullptr;
    }

    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    if (inputDevice == nullptr) {
        MMI_LOGE("create InputDevice ptr failed");
        return nullptr;
    }
    inputDevice->SetId(item->first);
    int32_t deviceType = static_cast<int32_t>(libinput_device_get_tags(
        static_cast<struct libinput_device *>(item->second)));
    inputDevice->SetDeviceType(deviceType);
    auto libinputDevice = static_cast<struct libinput_device *>(item->second);
    std::string name = libinput_device_get_name(libinputDevice);
    inputDevice->SetName(name);
    return inputDevice;
}

std::vector<int32_t> InputDeviceManager::GetDeviceIds()
{
    MMI_LOGI("GetDeviceIdList enter");
    std::vector<int32_t> deviceIdList;
    for (const auto &it : inputDeviceMap_) {
        deviceIdList.push_back(it.first);
    }
    return deviceIdList;
}

void InputDeviceManager::OnInputDeviceAdded(libinput_device* inputDevice)
{
    MMI_LOGI("OnInputDeviceAdded enter");
#ifdef OHOS_WESTEN_MODEL
    if (initFlag_) {
        return;
    }
#endif
    for (auto it : inputDeviceMap_) {
        if (static_cast<struct libinput_device *>(it.second) == inputDevice) {
            return;
        }
    }
    inputDeviceMap_.insert(std::pair<int32_t, libinput_device*>(nextId_,
        static_cast<struct libinput_device *>(inputDevice)));
    nextId_++;

    if (IsPointerDevice(static_cast<struct libinput_device *>(inputDevice))) {
        DrawWgr->TellDeviceInfo(true);
    }
}

void InputDeviceManager::OnInputDeviceRemoved(libinput_device* inputDevice)
{
    MMI_LOGI("OnInputDeviceRemoved enter");
#ifdef OHOS_WESTEN_MODEL
    if (initFlag_) {
        return;
    }
#endif
    for (auto it = inputDeviceMap_.begin(); it != inputDeviceMap_.end(); it++) {
        if (it->second == inputDevice) {
            inputDeviceMap_.erase(it);
            if (IsPointerDevice(inputDevice)) {
                DrawWgr->TellDeviceInfo(false);
            }
            break;
        }
    }
}

bool InputDeviceManager::IsPointerDevice(struct libinput_device* device)
{
    enum evdev_device_udev_tags udevTags = libinput_device_get_tags(device);
    MMI_LOGD("udev tag is%{public}d", static_cast<int32_t>(udevTags));
    return udevTags & (EVDEV_UDEV_TAG_MOUSE | EVDEV_UDEV_TAG_TRACKBALL | EVDEV_UDEV_TAG_POINTINGSTICK | 
    EVDEV_UDEV_TAG_TOUCHPAD | EVDEV_UDEV_TAG_TABLET_PAD);
}

int32_t InputDeviceManager::FindInputDeviceId(libinput_device* inputDevice)
{
    MMI_LOGI("begin");
    if (inputDevice == nullptr) {
        MMI_LOGI("Libinput_device is nullptr");
        return -1;
    }
    for (const auto& it : inputDeviceMap_) {
        if (static_cast<struct libinput_device *>(it.second) == inputDevice) {
            MMI_LOGI("Find input device id success");
            return it.first;
        }
    }
    MMI_LOGI("Find input device id failed");
    return -1;
}
}
}
