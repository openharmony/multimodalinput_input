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

#ifndef VIRTUAL_DEVICE_CONFIG_H
#define VIRTUAL_DEVICE_CONFIG_H

#include <cstdint>
#include <functional>
#include <iostream>
#include <vector>
#include <map>
#include <unistd.h>
#include <cstring>
#include <sys/stat.h>
#include <dirent.h>
#include <csignal>
#include <fstream>
#include <memory>
#include <cinttypes>
#include <cerrno>
#include <fcntl.h>
#include <sstream>
#include "securec.h"
#include "linux/input.h"
#include "linux/uinput.h"

#ifndef REL_WHEEL_HI_RES
#define REL_WHEEL_HI_RES    0x0b
#endif

#ifndef REL_HWHEEL_HI_RES
#define REL_HWHEEL_HI_RES    0x0c
#endif

namespace OHOS {
namespace MMI {
#define SYMBOL_FOLDER_PERMISSIONS 775
#define PARAMETERS_NUMBER 3
#define PARAMETERS_QUERY_NUMBER 2

struct ResolutionInfo {
    int16_t axisCode {};
    int32_t absResolution {};
};

struct AbsInfo {
    int32_t code {};
    int32_t minValue {};
    int32_t maxValue {};
    int32_t fuzz {};
    int32_t flat {};
};

const std::string g_folderPath = "/data/symbol/";
} // namespace MMI
} // namespace OHOS
#endif // VIRTUAL_DEVICE_CONFIG_H