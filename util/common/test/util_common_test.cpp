/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS;
} // namespace

class UtilCommonTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:IsInteger_001
 * @tc.desc:Verify enum add
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UtilCommonTest, IsInteger_001, TestSize.Level1)
{
    EXPECT_TRUE(IsInteger("0"));
    EXPECT_TRUE(IsInteger("123456"));
    EXPECT_TRUE(IsInteger("-0"));
    EXPECT_TRUE(IsInteger("-1"));
    EXPECT_TRUE(IsInteger("-918273645"));
    EXPECT_TRUE(IsInteger("  -918273645   "));
    EXPECT_FALSE(IsInteger("a  -918273645   "));
    EXPECT_FALSE(IsInteger("  -918273645   b"));
    EXPECT_FALSE(IsInteger("-"));
    EXPECT_FALSE(IsInteger("-918273645a"));
    EXPECT_FALSE(IsInteger("b-918273645"));
    EXPECT_FALSE(IsInteger("-91827a3645"));
    EXPECT_FALSE(IsInteger(".1"));
    EXPECT_FALSE(IsInteger("1."));
    EXPECT_FALSE(IsInteger("1.0"));
    EXPECT_FALSE(IsInteger("-1.0"));
}
} // namespace MMI
} // namespace OHOS