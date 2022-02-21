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

#include "knuckle_func_proc.h"
#include <gtest/gtest.h>
#include "libmmi_util.h"
#include "proto.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

    class KnuckleFuncProcTest : public testing::Test {
    public:
        static void SetUpTestCase(void) {}
        static void TearDownTestCase(void) {}
    };

    HWTEST_F(KnuckleFuncProcTest, Test_DeviceEventDispatchProcess_001, TestSize.Level1)
    {
        KnuckleFuncProc knuckleServer;
        const RawInputEvent event = { 0, 0, 0, 0 };
        int32_t retResult = knuckleServer.DeviceEventDispatchProcess(event);
        EXPECT_TRUE(retResult == RET_ERR);
    }

    HWTEST_F(KnuckleFuncProcTest, Test_GetDevType_001, TestSize.Level1)
    {
        KnuckleFuncProc knuckleServer;
        int32_t retResult = knuckleServer.GetDevType();
        EXPECT_EQ(retResult, static_cast<int32_t>(INPUT_DEVICE_CAP_KNUCKLE));
    }

    HWTEST_F(KnuckleFuncProcTest, Test_CheckEventCode_001, TestSize.Level1)
    {
        KnuckleFuncProc knuckleServer;
        RawInputEvent event = { };
        event.ev_code = static_cast<uint32_t>(MmiMessageId::ON_SCREEN_SHOT);
        int32_t retResult = knuckleServer.CheckEventCode(event);
        EXPECT_TRUE(retResult == RET_OK);
    }

    HWTEST_F(KnuckleFuncProcTest, Test_CheckEventCode_002, TestSize.Level1)
    {
        KnuckleFuncProc knuckleServer;
        const RawInputEvent event = { 0, 0, 0, 0 };
        int32_t retResult = knuckleServer.CheckEventCode(event);
        EXPECT_TRUE(retResult == RET_ERR);
    }
} // namespace
