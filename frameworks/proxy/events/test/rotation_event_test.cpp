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

#include "rotation_event.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS;

class RotationEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

RotationEvent rotationEvent;
HWTEST_F(RotationEventTest, Initialize_01, TestSize.Level1)
{
    rotationEvent.Initialize(1, 1, 1, "1", 1, 1, "1", 1, false);
}

HWTEST_F(RotationEventTest, GetRotationValue_F, TestSize.Level1)
{
    float retResult = rotationEvent.GetRotationValue();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(RotationEventTest, Initialize_02, TestSize.Level1)
{
    rotationEvent.Initialize(2, 2, 2, "2", 2, 2, "2", 2, true);
}

HWTEST_F(RotationEventTest, GetRotationValue_L, TestSize.Level1)
{
    float retResult = rotationEvent.GetRotationValue();
    EXPECT_TRUE(retResult == 2);
}

HWTEST_F(RotationEventTest, Initialize_03, TestSize.Level1)
{
    RotationEvent rotationEventTmp;
    rotationEventTmp.Initialize(rotationEvent);
}
} // namespace
