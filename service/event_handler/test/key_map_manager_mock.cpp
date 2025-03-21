/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "key_map_manager_mock.h"

namespace OHOS {
namespace MMI {
char* GetProFileAbsPath(const char* fileName, char* buf, int32_t length)
{
    std::cout<< "In here GetProFileAbsPath" <<std::endl;
    return KeyMgrMock::GetMock()->GetProFileAbsPath(fileName, buf, length);
}

extern "C" {
unsigned int libinput_device_get_id_vendor(struct libinput_device *device)
{
    return KeyMgrMock::GetMock()->libinput_device_get_id_vendor(device);
}

unsigned int libinput_device_get_id_product(struct libinput_device *device)
{
    return KeyMgrMock::GetMock()->libinput_device_get_id_product(device);
}

unsigned int libinput_device_get_id_version(struct libinput_device *device)
{
    return KeyMgrMock::GetMock()->libinput_device_get_id_version(device);
}

const char* libinput_device_get_name(struct libinput_device *device)
{
    return KeyMgrMock::GetMock()->libinput_device_get_name(device);
}

}
} // namespace MMI
} // namespace OHOS