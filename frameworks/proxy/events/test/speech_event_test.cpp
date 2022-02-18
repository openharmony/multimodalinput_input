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

#include "speech_event.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS;

class SpeechEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

SpeechEvent speechEvent;
HWTEST_F(SpeechEventTest, Initialize_01, TestSize.Level1)
{
    speechEvent.Initialize(1, 1, 1, 1, "1", 1, "1", 1, 1, "1", 1, false);
}

HWTEST_F(SpeechEventTest, GetAction_F, TestSize.Level1)
{
    int32_t retResult = speechEvent.GetAction();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(SpeechEventTest, GetScene_F, TestSize.Level1)
{
    int32_t retResult = speechEvent.GetScene();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(SpeechEventTest, GetActionProperty_F, TestSize.Level1)
{
    std::string retResult = speechEvent.GetActionProperty();
    EXPECT_STREQ(retResult.c_str(), "1");
}

HWTEST_F(SpeechEventTest, GetMatchMode_F, TestSize.Level1)
{
    int32_t retResult = speechEvent.GetMatchMode();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(SpeechEventTest, Initialize_02, TestSize.Level1)
{
    speechEvent.Initialize(2, 2, 2, 2, "2", 2, "2", 2, 2, "2", 2, true);
}

HWTEST_F(SpeechEventTest, GetAction_L, TestSize.Level1)
{
    int32_t retResult = speechEvent.GetAction();
    EXPECT_TRUE(retResult == 2);
}

HWTEST_F(SpeechEventTest, GetScene_L, TestSize.Level1)
{
    int32_t retResult = speechEvent.GetScene();
    EXPECT_TRUE(retResult == 2);
}

HWTEST_F(SpeechEventTest, GetActionProperty_L, TestSize.Level1)
{
    std::string retResult = speechEvent.GetActionProperty();
    EXPECT_STREQ(retResult.c_str(), "2");
}

HWTEST_F(SpeechEventTest, GetMatchMode_L, TestSize.Level1)
{
    int32_t retResult = speechEvent.GetMatchMode();
    EXPECT_TRUE(retResult == 2);
}

HWTEST_F(SpeechEventTest, Initialize_03, TestSize.Level1)
{
    SpeechEvent speechEventTmp;
    speechEventTmp.Initialize(speechEvent);
}
} // namespace
