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

#include "virtual_device.h"

namespace OHOS {
namespace MMI {
int32_t main(int32_t argc, const char *argv[])
{
    if (argc == 1 || argc > MAX_PARAMETER_NUMBER) {
        printf("Invaild Input Para, Plase Check the validity of the para!\n");
        return 0;
    }
    char Path[PATH_MAX] = {};
    if (realpath(g_folderpath.c_str(), Path) == nullptr) {
        MMI_LOGE("file path is error, path:%{public}s", g_folderpath.c_str());
        return -1;
    }
    DIR* dir = opendir(Path);
    bool flag = false;
    if (dir == nullptr) {
        mkdir(g_folderpath.c_str(), SYMBOL_FOLDER_PERMISSIONS);
        flag = true;
    }
    std::vector<std::string> argvList;
    for (uint16_t i = 0; i < argc; i++) {
        argvList.push_back(argv[i]);
    }
    if (!VirtualDevice::FindDevice(argvList)) {
        return 0;
    }
    constexpr std::int32_t usleepTime = 1500000;
    while (true) {
        usleep(usleepTime);
    }
}
} // namespace MMI
} // namespace OHOS
