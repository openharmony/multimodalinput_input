/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "oh_input_device_listener.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "OHInputDeviceListener"

namespace OHOS {
namespace MMI {
OHInputDeviceListener::OHInputDeviceListener() {}

OHInputDeviceListener::~OHInputDeviceListener() {}

void OHInputDeviceListener::OnDeviceAdded(int32_t deviceId, const std::string &type)
{
    if (addCallbacks_ != nullptr) {
        addCallbacks_(deviceId, type);
    }
}

void OHInputDeviceListener::OnDeviceRemoved(int32_t deviceId, const std::string &type)
{
    if (removeCallbacks_!= nullptr) {
        removeCallbacks_(deviceId, type);
    }
}

void OHInputDeviceListener::SetDeviceAddedCallback(
    const std::function<void(int32_t deviceId, const std::string &type)> &callback)
{
    addCallbacks_ = callback;
}

void OHInputDeviceListener::SetDeviceRemovedCallback(
    const std::function<void(int32_t deviceId, const std::string &type)> &callback)
{
    removeCallbacks_ = callback;
}
}
}