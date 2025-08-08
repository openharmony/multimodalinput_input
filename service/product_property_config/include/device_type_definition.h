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

 
#ifndef DEVICE_TYPE_DEFINITION_H
#define DEVICE_TYPE_DEFINITION_H
 
#include <unordered_map>
 
namespace OHOS {
namespace MMI {
enum class DeviceType {
    DEVICE_UNKNOWN = 0,
    DEVICE_PC = 1,
    DEVICE_SOFT_PC_PRO = 2,
    DEVICE_HARD_PC_PRO = 3,
    DEVICE_TABLET = 4,
    DEVICE_FOLD_PC = 5,
    DEVICE_M_PC = 6,
    DEVICE_FOLD_PC_VIRT = 7,
    DEVICE_M_TABLET = 8,
    DEVICE_Q_TABLET = 9,
};
 
static const std::unordered_map<std::string, DeviceType> gDeviceTypeMap {
    { "DEVICE_UNKNOWN", DeviceType::DEVICE_UNKNOWN },
    { "DEVICE_PC", DeviceType::DEVICE_PC },
    { "DEVICE_SOFT_PC_PRO", DeviceType::DEVICE_SOFT_PC_PRO },
    { "DEVICE_HARD_PC_PRO", DeviceType::DEVICE_HARD_PC_PRO },
    { "DEVICE_TABLET", DeviceType::DEVICE_TABLET },
    { "DEVICE_FOLD_PC", DeviceType::DEVICE_FOLD_PC },
    { "DEVICE_M_PC", DeviceType::DEVICE_M_PC },
    { "DEVICE_FOLD_PC_VIRT", DeviceType::DEVICE_FOLD_PC_VIRT },
    { "DEVICE_M_TABLET", DeviceType::DEVICE_M_TABLET },
    { "DEVICE_Q_TABLET", DeviceType::DEVICE_Q_TABLET }
};
 
} // namespace MMI
} // namespace OHOS
#endif // DEVICE_TYPE_DEFINITION_H