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

#include <gtest/gtest.h>

#include "key_event.h"
#include "key_event_value_transformation.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t KEY_ITEM_SIZE = 2;
} // namespace

class KeyEventValueTransformationTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_001
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_001, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_UNKNOWN);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_002
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_002, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_UP);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_UP);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_003
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_003, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_DOWN);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_DOWN);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_004
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_004, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_LEFT);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_LEFT);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_005
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_005, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_RIGHT);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_006
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_006, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_SPACE);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_SELECT);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_007
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_007, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_ESCAPE);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_ESCAPE);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_008
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_008, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_ALT_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_DPAD_LEFT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_BACK);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_009
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_009, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_ALT_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_DPAD_LEFT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_BACK);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_010
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_010, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_ALT_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_FORWARD);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_011
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_011, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_ALT_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_FORWARD);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_012
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_012, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_F10);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_MENU);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_013
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_013, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_SHIFT_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_F10);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_MENU);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_014
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_014, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_PAGE_UP);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_PAGE_UP);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_015
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_015, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_PAGE_DOWN);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_PAGE_DOWN);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_016
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_016, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_PLUS);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_ZOOM_OUT);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_017
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_017, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_PLUS);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_ZOOM_OUT);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_018
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_018, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_NUMPAD_ADD);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_ZOOM_OUT);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_019
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_019, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_NUMPAD_ADD);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_ZOOM_OUT);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_020
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_020, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_MINUS);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_ZOOM_IN);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_021
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_021, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_MINUS);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_ZOOM_IN);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_022
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_022, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_NUMPAD_SUBTRACT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_ZOOM_IN);
}

/**
 * @tc.name: KeyEventValueTransformationTest_KeyIntention_023
 * @tc.desc: Verify key intention
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_KeyIntention_023, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_NUMPAD_SUBTRACT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = keyItemsTransKeyIntention(KeyEvent->GetKeyItems());
    ASSERT_EQ(keyIntention, KeyEvent::INTENTION_ZOOM_IN);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_001
 * @tc.desc: Transfer key value
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_001, TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t nonExistingKeyValue = 999;
    KeyEventValueTransformation result = TransferKeyValue(nonExistingKeyValue);
}

/**
 * @tc.name: KeyEventValueTransformationTest_InputTransformationKeyValue_001
 * @tc.desc: Input transformationKey value
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_InputTransformationKeyValue_001,
     TestSize.Level1)
{
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t result = InputTransformationKeyValue(0);
    ASSERT_EQ(result, 240);
}
} // namespace MMI
} // namespace OHOS
