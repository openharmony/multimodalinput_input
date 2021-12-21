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
#include <gtest/gtest.h>
#include "mmi_point.h"

namespace {
using namespace testing::ext;
using namespace OHOS;

class MmiPointTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(MmiPointTest, ToString_GetX_001, TestSize.Level1)
{
    MmiPoint mmiPoint(1, 1);
    EXPECT_EQ(1, mmiPoint.GetX());
}

HWTEST_F(MmiPointTest, ToString_GetX_002, TestSize.Level1)
{
    MmiPoint mmiPoint(2, 3);
    EXPECT_EQ(2, mmiPoint.GetX());
}

HWTEST_F(MmiPointTest, ToString_GetX_003, TestSize.Level1)
{
    MmiPoint mmiPoint(4, 5, 6);
    EXPECT_EQ(4, mmiPoint.GetX());
}

HWTEST_F(MmiPointTest, ToString_GetY_001, TestSize.Level1)
{
    MmiPoint mmiPoint(1, 1);
    EXPECT_EQ(1, mmiPoint.GetY());
}

HWTEST_F(MmiPointTest, ToString_GetY_002, TestSize.Level1)
{
    MmiPoint mmiPoint(2, 3);
    EXPECT_EQ(3, mmiPoint.GetY());
}

HWTEST_F(MmiPointTest, ToString_GetY_003, TestSize.Level1)
{
    MmiPoint mmiPoint(4, 5, 6);
    EXPECT_EQ(5, mmiPoint.GetY());
}

HWTEST_F(MmiPointTest, ToString_GetZ_001, TestSize.Level1)
{
    MmiPoint mmiPoint(2, 3, 4);
    EXPECT_EQ(4, mmiPoint.GetZ());
}

HWTEST_F(MmiPointTest, ToString_GetZ_002, TestSize.Level1)
{
    MmiPoint mmiPoint(2, 3, 4);
    EXPECT_NE(3, mmiPoint.GetZ());
}

HWTEST_F(MmiPointTest, ToString_GetZ_003, TestSize.Level1)
{
    MmiPoint mmiPoint(4, 5, 6);
    EXPECT_EQ(6, mmiPoint.GetZ());
}

HWTEST_F(MmiPointTest, Setxy_001, TestSize.Level1)
{
    float offsetX = 1;
    float offsetY = 2;
    MmiPoint mmiPoint;
    mmiPoint.Setxy(offsetX, offsetY);
    EXPECT_EQ(1, mmiPoint.GetX());
}

HWTEST_F(MmiPointTest, Setxy_002, TestSize.Level1)
{
    float offsetX = 5;
    float offsetY = 6;
    MmiPoint mmiPoint;
    mmiPoint.Setxy(offsetX, offsetY);
    EXPECT_EQ(5, mmiPoint.GetX());
}

HWTEST_F(MmiPointTest, Setxyz_001, TestSize.Level1)
{
    float offsetX = 55;
    float offsetY = 66;
    float offsetZ = 77;
    MmiPoint mmiPoint;
    mmiPoint.Setxyz(offsetX, offsetY, offsetZ);
    EXPECT_EQ(66, mmiPoint.GetY());
}

HWTEST_F(MmiPointTest, Setxyz_002, TestSize.Level1)
{
    float offsetX = 22;
    float offsetY = 33;
    float offsetZ = 44;
    MmiPoint mmiPoint;
    mmiPoint.Setxyz(offsetX, offsetY, offsetZ);
    EXPECT_EQ(44, mmiPoint.GetZ());
}

HWTEST_F(MmiPointTest, ToString_001, TestSize.Level1)
{
    MmiPoint mmiPoint(22, 33, 44);
    std::string retResult = mmiPoint.ToString();
    ASSERT_STREQ("MmiPoint{ px =22.000000, py = 33.000000, pz = 44.000000}", retResult.c_str());
}

HWTEST_F(MmiPointTest, ToString_002, TestSize.Level1)
{
    MmiPoint mmiPoint(222, 332, 444);
    std::string retResult = mmiPoint.ToString();
    ASSERT_STREQ("MmiPoint{ px =222.000000, py = 332.000000, pz = 444.000000}", retResult.c_str());
}
} // namespace
