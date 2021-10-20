/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "libmmi_util.h"
#include "ai_func_proc.h"
#include "proto.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

    class AiFuncProcTest : public testing::Test {
    public:
        static void SetUpTestCase(void) {}
        static void TearDownTestCase(void) {}
    };

    HWTEST_F(AiFuncProcTest, Test_DeviceEventDispatchProcess_001, TestSize.Level1)
    {
        AIFuncProc aiServer;
        const RawInputEvent event = { 0, 0, 0, 0 };
        int32_t retResult = aiServer.DeviceEventDispatchProcess(event);
        EXPECT_TRUE(retResult == RET_ERR);
    }

    HWTEST_F(AiFuncProcTest, Test_GetDevType_001, TestSize.Level1)
    {
        AIFuncProc aiServer;
        int32_t retResult = aiServer.GetDevType();
        EXPECT_EQ(retResult, static_cast<int32_t>(INPUT_DEVICE_CAP_AISENSOR));
    }

    HWTEST_F(AiFuncProcTest, Test_CheckEventCode_001, TestSize.Level1)
    {
        AIFuncProc aiServer;
        RawInputEvent event = { };
        event.ev_code = static_cast<uint32_t>(MmiMessageId::ON_SHOW_MENU);
        int32_t retResult = aiServer.CheckEventCode(event);
        EXPECT_TRUE(retResult == RET_OK);
    }

    HWTEST_F(AiFuncProcTest, Test_CheckEventCode_002, TestSize.Level1)
    {
        AIFuncProc aiServer;
        RawInputEvent event = { 0, 0, 0, 0 };
        int32_t retResult = aiServer.CheckEventCode(event);
        EXPECT_TRUE(retResult == RET_ERR);
    }
}
