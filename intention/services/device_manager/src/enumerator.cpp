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

#include "enumerator.h"

#include <dirent.h>
#include <sys/stat.h>

#include "devicestatus_define.h"
#include "fi_log.h"
#include "napi_constants.h"
#include "utility.h"

#undef LOG_TAG
#define LOG_TAG "Enumerator"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

void Enumerator::SetDeviceMgr(IDeviceMgr *devMgr)
{
    CALL_DEBUG_ENTER;
    CHKPV(devMgr);
    devMgr_ = devMgr;
}

void Enumerator::ScanDevices()
{
    CALL_DEBUG_ENTER;
    ScanAndAddDevices();
}

void Enumerator::ScanAndAddDevices()
{
    CALL_DEBUG_ENTER;
    DIR *dir = opendir(DEV_INPUT_PATH.c_str());
    CHKPV(dir);
    struct dirent *dent;

    while ((dent = readdir(dir)) != nullptr) {
        const std::string devNode { dent->d_name };
        const std::string devPath { DEV_INPUT_PATH + devNode };
        struct stat statbuf;

        if (stat(devPath.c_str(), &statbuf) != 0) {
            continue;
        }
        if (!S_ISCHR(statbuf.st_mode)) {
            continue;
        }
        AddDevice(devNode);
    }

    closedir(dir);
}

void Enumerator::AddDevice(const std::string &devNode) const
{
    CALL_DEBUG_ENTER;
    CHKPV(devMgr_);
    devMgr_->AddDevice(devNode);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
