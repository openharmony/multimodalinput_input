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

#include "injection_event_dispatch.h"
#include "error_multimodal.h"
#include "mmi_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, OHOS::MMI::MMI_LOG_DOMAIN, "MmiEventSimulateDemoMain" };
} // namespace

int32_t main(int32_t argc, const char* argv[])
{
    using namespace OHOS::MMI;
    do {
        SetThreadName("main");
        if (argc < ARGV_VALID) {
            MMI_HILOGI("Invalid Input Para, Please Check the validity of the para! errCode:%d", PARAM_INPUT_FAIL);
            break;
        }
        std::vector<std::string> argvs;
        for (int32_t i = 0; i < argc; i++) {
            argvs.push_back(argv[i]);
        }
        InjectionEventDispatch injection;
        injection.Init();
        if (!(injection.VerifyArgvs(argc, argvs))) {
            MMI_HILOGI("Invalid Input Para, Please Check the validity of the para! errCode:%d", PARAM_INPUT_FAIL);
            break;
        }
        injection.Run();
    } while (0);

    return RET_OK;
}
