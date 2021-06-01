/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "key_event.h"

#include <gtest/gtest.h>

namespace OHOS {
using namespace testing::ext;

class KeyEventTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void KeyEventTest::SetUpTestCase() {}

void KeyEventTest::TearDownTestCase() {}

void KeyEventTest::SetUp() {}

void KeyEventTest::TearDown() {}

/**
 * @tc.name: KeyEventTest_IsKeyDown_001
 * @tc.desc: key pressed.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyEventTest,
        KeyEventTest_IsKeyDown_001, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyEvent event;
    keyProperty.isPressed = true;
    keyProperty.keyCode = KeyEvent::CODE_BACK;
    event.Initialize(multiProperty, keyProperty);

    EXPECT_EQ(true, event.IsKeyDown());
    EXPECT_EQ(KeyEvent::CODE_BACK, event.GetKeyCode());
}

/**
 * @tc.name: KeyEventTest_GetMaxKeyCode_002
 * @tc.desc: get max key code.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyEventTest,
        KeyEventTest_GetMaxKeyCode_002, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyEvent event;
    keyProperty.isPressed = true;
    keyProperty.keyCode = KeyEvent::NOW_MAX_CODE;
    event.Initialize(multiProperty, keyProperty);

    EXPECT_EQ(KeyEvent::NOW_MAX_CODE, event.GetMaxKeyCode());
}

/**
 * @tc.name: KeyEventTest_GetKeyCode_003
 * @tc.desc: get key code.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyEventTest,
        KeyEventTest_GetKeyCode_003, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyEvent event;
    keyProperty.isPressed = true;
    keyProperty.keyCode = KeyEvent::CODE_HOME;
    event.Initialize(multiProperty, keyProperty);

    EXPECT_EQ(KeyEvent::CODE_HOME, event.GetKeyCode());
}

/**
 * @tc.name: KeyEventTest_GetKeyDownDuration_004
 * @tc.desc: get key down duration.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyEventTest,
        KeyEventTest_GetKeyDownDuration_004, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyEvent event;
    keyProperty.isPressed = true;
    keyProperty.keyDownDuration = 200;
    keyProperty.keyCode = KeyEvent::CODE_BACK;
    event.Initialize(multiProperty, keyProperty);

    EXPECT_EQ(200, event.GetKeyDownDuration());
}

/**
 * @tc.name: KeyEventTest_Marshalling_005
 * @tc.desc: marshalling.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyEventTest,
        KeyEventTest_Marshalling_005, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyEvent event;
    keyProperty.isPressed = true;
    keyProperty.keyCode = KeyEvent::CODE_BACK;
    event.Initialize(multiProperty, keyProperty);

    Parcel parrcel;
    EXPECT_EQ(true, event.Marshalling(parrcel));
}

/**
 * @tc.name: KeyEventTest_Unmarshalling_006
 * @tc.desc: unmarshalling.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyEventTest,
        KeyEventTest_Unmarshalling_006, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyEvent event;
    keyProperty.isPressed = true;
    keyProperty.keyCode = KeyEvent::CODE_BACK;
    event.Initialize(multiProperty, keyProperty);

    Parcel parcel;
    ASSERT_NE(nullptr, event.Unmarshalling(parcel));
}
} // namespace OHOS
