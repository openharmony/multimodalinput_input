/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "define_multimodal.h"
#include "touch_event_normalize.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class TouchEventNormalizeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

private:
    bool prePinchSwitch_ { true };
    bool preSwipeSwitch_ { true };
    bool preRotateSwitch_ { true };
};

void TouchEventNormalizeTest::SetUpTestCase(void)
{
}

void TouchEventNormalizeTest::TearDownTestCase(void)
{
}

void TouchEventNormalizeTest::SetUp()
{
    TouchEventHdr->GetTouchpadPinchSwitch(prePinchSwitch_);
    TouchEventHdr->GetTouchpadSwipeSwitch(preSwipeSwitch_);
    TouchEventHdr->GetTouchpadRotateSwitch(preRotateSwitch_);
}

void TouchEventNormalizeTest::TearDown()
{
    TouchEventHdr->SetTouchpadPinchSwitch(prePinchSwitch_);
    TouchEventHdr->SetTouchpadSwipeSwitch(preSwipeSwitch_);
    TouchEventHdr->SetTouchpadRotateSwitch(preRotateSwitch_);
}

/**
 * @tc.name: TouchEventNormalizeTest_SetTouchpadPinchSwitch_01
 * @tc.desc: Test SetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_SetTouchpadPinchSwitch_01, TestSize.Level1)
{
    bool flag = false;
    ASSERT_TRUE(TouchEventHdr->SetTouchpadPinchSwitch(flag) == RET_OK);
}

/**
 * @tc.name: TouchEventNormalizeTest_GetTouchpadPinchSwitch_02
 * @tc.desc: Test GetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_GetTouchpadPinchSwitch_02, TestSize.Level1)
{
    bool flag = true;
    TouchEventHdr->SetTouchpadPinchSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(TouchEventHdr->GetTouchpadPinchSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: TouchEventNormalizeTest_SetTouchpadSwipeSwitch_03
 * @tc.desc: Test SetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_SetTouchpadSwipeSwitch_03, TestSize.Level1)
{
    bool flag = false;
    ASSERT_TRUE(TouchEventHdr->SetTouchpadSwipeSwitch(flag) == RET_OK);
}

/**
 * @tc.name: TouchEventNormalizeTest_GetTouchpadSwipeSwitch_04
 * @tc.desc: Test GetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_GetTouchpadSwipeSwitch_04, TestSize.Level1)
{
    bool flag = true;
    TouchEventHdr->SetTouchpadSwipeSwitch(flag);
    bool newFlag = true;
    ASSERT_TRUE(TouchEventHdr->GetTouchpadSwipeSwitch(flag) == RET_OK);
    ASSERT_TRUE(flag == newFlag);
}

/**
 * @tc.name: TouchEventNormalizeTest_SetTouchpadRotateSwitch_05
 * @tc.desc: Test SetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_SetTouchpadRotateSwitch_05, TestSize.Level1)
{
    bool rotateSwitch = false;
    ASSERT_TRUE(TouchEventHdr->SetTouchpadRotateSwitch(rotateSwitch) == RET_OK);
}

/**
 * @tc.name: TouchEventNormalizeTest_GetTouchpadRotateSwitch_06
 * @tc.desc: Test GetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchEventNormalizeTest, TouchEventNormalizeTest_GetTouchpadRotateSwitch_06, TestSize.Level1)
{
    bool rotateSwitch = true;
    TouchEventHdr->SetTouchpadRotateSwitch(rotateSwitch);
    bool newRotateSwitch = true;
    ASSERT_TRUE(TouchEventHdr->GetTouchpadRotateSwitch(rotateSwitch) == RET_OK);
    ASSERT_TRUE(rotateSwitch == newRotateSwitch);
}
}
}