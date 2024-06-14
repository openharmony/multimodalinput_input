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

#include "injection_event_dispatch.h"

#include "error_multimodal.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MmiEventSimulateDemoMain"

int32_t main(int32_t argc, char* argv[])
{
    using namespace OHOS::MMI;
    do {
        SetThreadName("main");
        InjectionToolsHelpFunc helpFunc;
        if (!helpFunc.CheckInjectionCommand(argc, argv)) {
            MMI_HILOGE("Invalid Input Para, Please Check the validity of the para! errCode:%d", PARAM_INPUT_FAIL);
            std::cout << "Try './mmi-event-injection --help' for more information" << std::endl;
            return RET_ERR;
        }
        InjectionEventDispatch injection;
        injection.SetArgvs(helpFunc.GetArgvs());
        injection.Init();
        if (!injection.VerifyArgvs()) {
            MMI_HILOGE("Parameter and function validation failed");
            return RET_ERR;
        }
        injection.Run();
    } while (0);
    return RET_OK;
}
