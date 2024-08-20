/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventValueTransformationTest"
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_UP);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_DOWN);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_LEFT);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_SPACE);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_ESCAPE);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_ALT_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_DPAD_LEFT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_ALT_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_DPAD_LEFT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_ALT_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_ALT_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_DPAD_RIGHT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_SHIFT_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_F10);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_SHIFT_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_F10);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_PAGE_UP);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_PAGE_DOWN);
    KeyEvent->AddKeyItem(item);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_PLUS);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_PLUS);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_NUMPAD_ADD);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_NUMPAD_ADD);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_MINUS);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_MINUS);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_LEFT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_NUMPAD_SUBTRACT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    KeyEvent::KeyItem item[KEY_ITEM_SIZE];
    item[0].SetKeyCode(KeyEvent::KEYCODE_CTRL_RIGHT);
    KeyEvent->AddKeyItem(item[0]);
    item[1].SetKeyCode(KeyEvent::KEYCODE_NUMPAD_SUBTRACT);
    KeyEvent->AddKeyItem(item[1]);
    int32_t keyIntention = KeyItemsTransKeyIntention(KeyEvent->GetKeyItems());
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t nonExistingKeyValue = 999;
    KeyEventValueTransformation result = TransferKeyValue(nonExistingKeyValue);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_002
 * @tc.desc: Transfer F1 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 59;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F1);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_003
 * @tc.desc: Transfer F2 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 60;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F2);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_004
 * @tc.desc: Transfer F3 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 61;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F3);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_005
 * @tc.desc: Transfer F4 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 62;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F4);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_006
 * @tc.desc: Transfer F5 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_006, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 63;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F5);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_007
 * @tc.desc: Transfer F6 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_007, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 64;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F6);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_008
 * @tc.desc: Transfer F7 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_008, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 65;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F7);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_009
 * @tc.desc: Transfer F8 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_009, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 66;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F8);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_010
 * @tc.desc: Transfer F9 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_010, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 67;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F9);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_011
 * @tc.desc: Transfer F10 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_011, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 68;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F10);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_012
 * @tc.desc: Transfer F11 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_012, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 87;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F11);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_013
 * @tc.desc: Transfer F12 key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_013, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 88;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_F12);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_014
 * @tc.desc: Transfer Brightness Down key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_014, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 224;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_015
 * @tc.desc: Transfer Brightness Up key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_015, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 225;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_BRIGHTNESS_UP);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_016
 * @tc.desc: Transfer Volume Mute key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_016, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 113;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_VOLUME_MUTE);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_017
 * @tc.desc: Transfer Volume Down key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_017, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 114;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_VOLUME_DOWN);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_018
 * @tc.desc: Transfer Volume Up key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_018, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 115;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_VOLUME_UP);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_019
 * @tc.desc: Transfer Mute key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_019, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 248;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_MUTE);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_020
 * @tc.desc: Transfer Switch Video Mode key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_020, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 595;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_SWITCHVIDEOMODE);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_021
 * @tc.desc: Transfer Search key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_021, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 594;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_SEARCH);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_022
 * @tc.desc: Transfer Media Record key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_022, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 597;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_MEDIA_RECORD);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_023
 * @tc.desc: Transfer Sysrq key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_023, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 99;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_SYSRQ);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_024
 * @tc.desc: Transfer Insert key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_024, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 110;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_INSERT);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_025
 * @tc.desc: Transfer Sound key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_025, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 249;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_SOUND);
}

/**
 * @tc.name: KeyEventValueTransformationTest_TransferKeyValue_026
 * @tc.desc: Transfer Assistant key value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventValueTransformationTest, KeyEventValueTransformationTest_TransferKeyValue_026, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t keyValue = 251;
    KeyEventValueTransformation result = TransferKeyValue(keyValue);
    EXPECT_EQ(result.sysKeyValue, KeyEvent::KEYCODE_ASSISTANT);
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
    CALL_DEBUG_ENTER;
    auto KeyEvent = KeyEvent::Create();
    ASSERT_NE(KeyEvent, nullptr);
    int32_t result = InputTransformationKeyValue(0);
    ASSERT_EQ(result, 240);
}
} // namespace MMI
} // namespace OHOS
