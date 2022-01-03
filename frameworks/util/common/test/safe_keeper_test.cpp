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

#include "safe_keeper.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class SafeKeeperTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class SafeKeeperUnitTest : public SafeKeeper {
public:
    bool IsExistUnitTest(uint64_t tid) const
    {
        return IsExist(tid);
    }
    SafeEvent *GetEventUnitTest(uint64_t tid)
    {
        return GetEvent(tid);
    }
};

void Fun(uint32_t kId, uint64_t tId, const std::string& strId)
{
}

HWTEST_F(SafeKeeperTest, Single_RegisterEvent_001, TestSize.Level1)
{
    SafeKpr->Init(Fun);
    bool retResult = SafeKpr->RegisterEvent(1, "123");
    ASSERT_TRUE(retResult);
}

HWTEST_F(SafeKeeperTest, Single_RegisterEvent_002, TestSize.Level1)
{
    SafeKpr->Init(Fun);
    bool retResult = SafeKpr->RegisterEvent(0, "777");
    ASSERT_TRUE(retResult);
}

HWTEST_F(SafeKeeperTest, Single_ReportHealthStatus_001, TestSize.Level1)
{
    SafeKpr->ReportHealthStatus(1001);
}

HWTEST_F(SafeKeeperTest, Single_ReportHealthStatus_002, TestSize.Level1)
{
    SafeKpr->ReportHealthStatus(-1001);
}

HWTEST_F(SafeKeeperTest, Single_ProcessEvents, TestSize.Level1)
{
    SafeKpr->ProcessEvents();
}

HWTEST_F(SafeKeeperTest, Single_ClearAll, TestSize.Level1)
{
    SafeKpr->ClearAll();
}

HWTEST_F(SafeKeeperTest, Init, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
}

HWTEST_F(SafeKeeperTest, RegisterEvent_001, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
    bool retResult = safObj.RegisterEvent(1, "333");
    EXPECT_TRUE(retResult);
}

HWTEST_F(SafeKeeperTest, RegisterEvent_002, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
    bool retResult = safObj.RegisterEvent(0, "#$2111");
    EXPECT_TRUE(retResult);
}

HWTEST_F(SafeKeeperTest, ReportHealthStatus_001, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
    safObj.ReportHealthStatus(1);
}

HWTEST_F(SafeKeeperTest, ReportHealthStatus_002, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
    safObj.ReportHealthStatus(-1001);
}

HWTEST_F(SafeKeeperTest, ProcessEvents, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
    safObj.ProcessEvents();
}

HWTEST_F(SafeKeeperTest, IsExist_001, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
    bool retResult = safObj.IsExistUnitTest(1001);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SafeKeeperTest, IsExist_002, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
    bool retResult = safObj.IsExistUnitTest(-1001);
    EXPECT_FALSE(retResult);
}

HWTEST_F(SafeKeeperTest, GetEvent_001, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
    auto retResult = safObj.GetEventUnitTest(1);
    EXPECT_TRUE(retResult == nullptr);
}

HWTEST_F(SafeKeeperTest, GetEvent_002, TestSize.Level1)
{
    SafeKeeperUnitTest safObj;
    safObj.Init(Fun);
    auto retResult = safObj.GetEventUnitTest(-1001);
    EXPECT_TRUE(retResult == nullptr);
}
} // namespace
