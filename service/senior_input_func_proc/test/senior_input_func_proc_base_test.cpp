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

#include "senior_input_func_proc_base.h"
#include <gtest/gtest.h>
#include "knuckle_func_proc.h"
#include "libmmi_util.h"
#include "mmi_server.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

    const uint32_t DEVICE_FD_INDEX_1 = 1;
    const uint32_t DEVICE_FD_INDEX_2 = 2;
    const int32_t DEVICE_FD_ERROR = -1;
    class SeniorInputFuncProcBaseTest : public testing::Test {
    public:
        static void SetUpTestCase(void) {}
        static void TearDownTestCase(void) {}
    };

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_Init_001, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        UDSServer sess;
        bool ret = seniorInputFunc.Init(sess);
        EXPECT_EQ(ret, true);
    }

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_DeviceInit_001, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        auto ptr = seniorInputFunc.Create<KnuckleFuncProc>();
        bool ret = seniorInputFunc.DeviceInit(DEVICE_FD_INDEX_1, ptr);
        seniorInputFunc.DeviceDisconnect(DEVICE_FD_INDEX_1);
        EXPECT_EQ(ret, true);
    }

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_DeviceInit_002, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        auto ptr = seniorInputFunc.Create<KnuckleFuncProc>();
        seniorInputFunc.DeviceInit(DEVICE_FD_INDEX_1, ptr);
        bool ret = seniorInputFunc.DeviceInit(DEVICE_FD_INDEX_1, ptr);
        seniorInputFunc.DeviceDisconnect(DEVICE_FD_INDEX_1);
        EXPECT_EQ(ret, false);
    }

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_DeviceEventDispatch_001, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        RawInputEvent event = {};
        auto ptr = seniorInputFunc.Create<KnuckleFuncProc>();
        seniorInputFunc.DeviceInit(DEVICE_FD_INDEX_1, ptr);
        bool ret = seniorInputFunc.DeviceEventDispatch(DEVICE_FD_INDEX_1, event);
        seniorInputFunc.DeviceDisconnect(DEVICE_FD_INDEX_1);
        EXPECT_EQ(ret, true);
    }

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_DeviceEventDispatch_002, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        RawInputEvent event = {};
        auto ptr = seniorInputFunc.Create<KnuckleFuncProc>();
        seniorInputFunc.DeviceInit(DEVICE_FD_INDEX_1, ptr);
        bool ret = seniorInputFunc.DeviceEventDispatch(DEVICE_FD_INDEX_2, event);
        seniorInputFunc.DeviceDisconnect(DEVICE_FD_INDEX_1);
        EXPECT_EQ(ret, false);
    }

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_GetDevType_001, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        seniorInputFunc.GetDevType();
    }

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_SetSessionFd_001, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        seniorInputFunc.SetSessionFd(DEVICE_FD_INDEX_1);
    }

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_GetSessionFd_001, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        seniorInputFunc.SetSessionFd(DEVICE_FD_INDEX_1);
        int32_t ret = seniorInputFunc.GetSessionFd();
        EXPECT_EQ(ret, DEVICE_FD_INDEX_1);
    }

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_GetSessionFd_002, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        seniorInputFunc.SetSessionFd(DEVICE_FD_ERROR);
        int32_t ret = seniorInputFunc.GetSessionFd();
        EXPECT_EQ(ret, RET_ERR);
    }

    HWTEST_F(SeniorInputFuncProcBaseTest, Test_DeviceEventDispatchProcess_001, TestSize.Level1)
    {
        SeniorInputFuncProcBase seniorInputFunc;
        const RawInputEvent event = { 0 };
        seniorInputFunc.DeviceEventDispatchProcess(event);
    }
} // namespace
