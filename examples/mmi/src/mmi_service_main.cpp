/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "mmi_service.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MmiServiceDemo"
namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t SLEEP_TIME = 10 * 60;
} // namespace
} // namespace MMI
} // namespace OHOS

int32_t main(int32_t argc, const char *argv[])
{
    auto service = OHOS::MMIService>::GetInstance();
    service->OnStart();
    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(SLEEP_TIME));
    }
    service->OnStop();
    service->OnDump();
    MMI_HILOGD("mmi-service stopping. argc:%{public}d, argv:%{public}s", argc, argv[0]);
    return RET_OK;
}
