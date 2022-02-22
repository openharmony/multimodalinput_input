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

#include "stylus_event.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS;

class StylusEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

StylusEvent stylusEvent;
HWTEST_F(StylusEventTest, GetAction_F, TestSize.Level1)
{
    int32_t retResult = stylusEvent.GetAction();
    EXPECT_FALSE(retResult == 1);
}

HWTEST_F(StylusEventTest, GetButtons_F, TestSize.Level1)
{
    int32_t retResult = stylusEvent.GetButtons();
    EXPECT_FALSE(retResult == 1);
}

HWTEST_F(StylusEventTest, GetAction_L, TestSize.Level1)
{
    int32_t retResult = stylusEvent.GetAction();
    EXPECT_FALSE(retResult == 2);
}

HWTEST_F(StylusEventTest, GetButtons_L, TestSize.Level1)
{
    int32_t retResult = stylusEvent.GetButtons();
    EXPECT_FALSE(retResult == 2);
}

HWTEST_F(StylusEventTest, InitializeTmp, TestSize.Level1)
{
    StylusEvent stylusEventTmp;
    stylusEventTmp.Initialize(stylusEvent);
}
} // namespace
