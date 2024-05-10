/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdio>

#include <gtest/gtest.h>
#include "libinput.h"

#include "define_multimodal.h"
#include "key_event_normalize.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class KeyEventNormalizeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test shieldMode_Equal_lastShieldMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, shieldMode_Equal_lastShieldMode, TestSize.Level1)
{
    bool isShield = true;
    int32_t shieldMode = -1;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test shieldMode_NotEqual_lastShieldMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, shieldMode_NotEqual_lastShieldMode, TestSize.Level1)
{
    bool isShield = false;
    int32_t shieldMode = 3;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test SetShieldStatus_FACTORY_MODE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, SetShieldStatus_FACTORY_MODE, TestSize.Level1)
{
    bool isShield = false;
    int32_t shieldMode = 0;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test SetShieldStatus_OOBE_MODE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, SetShieldStatus_OOBE_MODE, TestSize.Level1)
{
    bool isShield = false;
    int32_t shieldMode = 1;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test SetShieldStatus_NotFound
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, SetShieldStatus_NotFound, TestSize.Level1)
{
    bool isShield = false;
    int32_t shieldMode = -1;
    int32_t result = KeyEventHdr->SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test GetShieldStatus_FACTORY_MODE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, GetShieldStatus_FACTORY_MODE, TestSize.Level1)
{
    bool isShield = false;
    int32_t shieldMode = 0;
    int32_t result = KeyEventHdr->GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test GetShieldStatus_OOBE_MODE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, GetShieldStatus_OOBE_MODE, TestSize.Level1)
{
    bool isShield = false;
    int32_t shieldMode = 1;
    int32_t result = KeyEventHdr->GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventNormalizeTest
 * @tc.desc: Test GetShieldStatus_NotFound
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventNormalizeTest, GetShieldStatus_NotFound, TestSize.Level1)
{
    bool isShield = false;
    int32_t shieldMode = -1;
    int32_t result = KeyEventHdr->GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}
}
}