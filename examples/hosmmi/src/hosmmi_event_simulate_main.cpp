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

#include "injection_event_dispatch.h"
#include "log.h"

namespace {
[[maybe_unused]] static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, OHOS::MMI::MMI_LOG_DOMAIN, "HosMmiEventSimulateDemoMain" 
};
}

int32_t main(int32_t argc, const char* argv[])
{
#ifdef OHOS_BUILD_MMI_DEBUG
    VerifyLogManagerRun();
#endif

    do {
        OHOS::MMI::SetThreadName("main");
        if (argc < OHOS::MMI::ARGV_VALID) {
            MMI_LOGI("Invaild Input Para, Plase Check the validity of the para! errCode:%d\n", OHOS::PARAM_INPUT_FAIL);
            break;
        }
        std::vector<std::string> argvs;
        for (int32_t i = 0; i < argc; i++) {
            argvs.push_back(argv[i]);
        }
        OHOS::MMI::InjectionEventDispatch injection;
        injection.Init();
        if (!(injection.VirifyArgvs(argc, argvs))) {
            MMI_LOGI("Invaild Input Para, Plase Check the validity of the para! errCode:%d\n", OHOS::PARAM_INPUT_FAIL);
            break;
        }
        injection.Run();
        if (OHOS::MMI::TestAuxToolClient::GetInstance().ThreadIsEnd()) {
            MMI_LOGI("TestAuxToolClient thread is end.");
        }
    } while (0);

#ifdef OHOS_BUILD_MMI_DEBUG
    OHOS::MMI::LogManager::GetInstance().Stop();

    if (OHOS::MMI::LogManager::GetInstance().ThreadIsEnd()) {
        MMI_LOGI("LogManager thread is end.");
    }
#endif

    return RET_OK;
}
