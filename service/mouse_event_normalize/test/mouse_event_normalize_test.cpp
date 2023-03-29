/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "libinput.h"
#include "mouse_event_normalize.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class MouseEventNormalizeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void MouseEventNormalizeTest::SetUpTestCase(void)
{
}

void MouseEventNormalizeTest::TearDownTestCase(void)
{
}

void MouseEventNormalizeTest::SetUp()
{
}

void MouseEventNormalizeTest::TearDown()
{
}

/**
 * @tc.name: MouseEventNormalizeTest_GetDisplayId()_001
 * @tc.desc: Test GetDisplayId()
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetDisplayId_001, TestSize.Level1)
{
    int32_t idNames = -1;
    ASSERT_EQ(MouseEventHdr->GetDisplayId(), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetPointerEvent_002
 * @tc.desc: Test GetPointerEvent()
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetPointerEvent_002, TestSize.Level1)
{
    std::shared_ptr<PointerEvent> idNames = nullptr;
    ASSERT_EQ(MouseEventHdr->GetPointerEvent(), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_OnEvent_003
 * @tc.desc: Test OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_OnEvent_003, TestSize.Level1)
{
    libinput_event *event = {};
    int idNames = -1;
    ASSERT_EQ(MouseEventHdr->OnEvent(event), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_NormalizeMoveMouse_004
 * @tc.desc: Test NormalizeMoveMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_NormalizeMoveMouse_004, TestSize.Level1)
{
    bool idNames = false;
    ASSERT_EQ(MouseEventHdr->NormalizeMoveMouse(0, 0), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_Dump_005
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_Dump_005, TestSize.Level1)
{
    std::vector<std::string> args = {};
    std::vector<std::string> idNames = {};
    MouseEventHdr->Dump(0, args);
    ASSERT_EQ(args, idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetPointerSpeed_006
 * @tc.desc: Test SetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetPointerSpeed_006, TestSize.Level1)
{
    int32_t idNames = 0;
    ASSERT_EQ(MouseEventHdr->SetPointerSpeed(2), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_GetPointerSpeed_007
 * @tc.desc: Test GetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_GetPointerSpeed_007, TestSize.Level1)
{
    MouseEventHdr->SetPointerSpeed(2);
    int32_t idNames = 2;
    ASSERT_EQ(MouseEventHdr->GetPointerSpeed(), idNames);
}

/**
 * @tc.name: MouseEventNormalizeTest_SetPointerLocation_008
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseEventNormalizeTest, MouseEventNormalizeTest_SetPointerLocation_008, TestSize.Level1)
{
    // MouseEventHdr->SetAbsolutionLocation(0, 0);
    int32_t idNames = -1;
    ASSERT_EQ(MouseEventHdr->SetPointerLocation(0, 0), idNames);
}
}
}