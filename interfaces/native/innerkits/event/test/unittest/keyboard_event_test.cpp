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

#include "keyboard_event.h"

#include <gtest/gtest.h>

namespace OHOS {
using namespace testing::ext;

class KeyBoardEventTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void KeyBoardEventTest::SetUpTestCase() {}

void KeyBoardEventTest::TearDownTestCase() {}

void KeyBoardEventTest::SetUp() {}

void KeyBoardEventTest::TearDown() {}

/**
 * @tc.name: KeyBoardEventTest_IsHandledByIme_001
 * @tc.desc:is handled by ime.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyBoardEventTest,
        KeyBoardEventTest_IsHandledByIme_001, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyBoardProperty keyBoardProperty;
    KeyBoardEvent event;
    keyBoardProperty.handledByIme = true;
    event.Initialize(multiProperty, keyProperty, keyBoardProperty);

    EXPECT_EQ(true, event.IsHandledByIme());
}

/**
 * @tc.name: KeyBoardEventTest_IsNoncharacterKeyPressed_002
 * @tc.desc: key pressed.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyBoardEventTest,
        KeyBoardEventTest_IsNoncharacterKeyPressed_002, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyBoardProperty keyBoardProperty;
    KeyBoardEvent event;
    keyBoardProperty.isSingleNonCharacter = true;
    event.Initialize(multiProperty, keyProperty, keyBoardProperty);

    EXPECT_EQ(true, event.IsNoncharacterKeyPressed(1));
}

/**
 * @tc.name: KeyBoardEventTest_IsNoncharacterKeyPressed_003
 * @tc.desc: key pressed.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyBoardEventTest,
        KeyBoardEventTest_IsNoncharacterKeyPressed_003, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyBoardProperty keyBoardProperty;
    KeyBoardEvent event;
    keyBoardProperty.isTwoNonCharacters = true;
    event.Initialize(multiProperty, keyProperty, keyBoardProperty);

    EXPECT_EQ(true, event.IsNoncharacterKeyPressed(1, 2));
}

/**
 * @tc.name: KeyBoardEventTest_IsNoncharacterKeyPressed_004
 * @tc.desc: key pressed.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyBoardEventTest,
        KeyBoardEventTest_IsNoncharacterKeyPressed_004, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyBoardProperty keyBoardProperty;
    KeyBoardEvent event;
    keyBoardProperty.isThreeNonCharacters = true;
    event.Initialize(multiProperty, keyProperty, keyBoardProperty);

    EXPECT_EQ(true, event.IsNoncharacterKeyPressed(1, 2, 3));
}

/**
 * @tc.name: KeyBoardEventTest_GetUnicode_005
 * @tc.desc: key pressed.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyBoardEventTest,
        KeyBoardEventTest_GetUnicoded_005, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyBoardProperty keyBoardProperty;
    KeyBoardEvent event;
    keyBoardProperty.unicode = 123;
    event.Initialize(multiProperty, keyProperty, keyBoardProperty);

    EXPECT_EQ(123, event.GetUnicode());
}

/**
 * @tc.name: KeyBoardEventTest_Marshalling_006
 * @tc.desc: marshalling.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyBoardEventTest,
        KeyBoardEventTest_Marshalling_006, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyBoardProperty keyBoardProperty;
    KeyBoardEvent event;
    keyBoardProperty.unicode = 123;
    event.Initialize(multiProperty, keyProperty, keyBoardProperty);

    Parcel parcel;
    EXPECT_EQ(false, event.Marshalling(parcel));
}

/**
 * @tc.name: KeyBoardEventTest_Unmarshalling_007
 * @tc.desc: unmarshalling.
 * @tc.type: FUNC
 * @tc.require: AR000FSG7F
 */
HWTEST_F(KeyBoardEventTest,
        KeyBoardEventTest_Unmarshalling_007, TestSize.Level2)
{
    MultimodalProperty multiProperty;
    KeyProperty keyProperty;
    KeyBoardProperty keyBoardProperty;
    KeyBoardEvent event;
    keyBoardProperty.unicode = 123;
    event.Initialize(multiProperty, keyProperty, keyBoardProperty);

    Parcel parcel;
    ASSERT_NE(nullptr, event.Unmarshalling(parcel));
}
} // namespace OHOS
