/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "i_input_service_context.h"
#include "key_event.h"
#include "property_name_mapper_impl.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PropertyNameMapperImplTest"

namespace OHOS {
namespace MMI {
extern "C" {
IPropertyNameMapper* CreateInstance(IInputServiceContext *env);
void DestroyInstance(IPropertyNameMapper *instance);
}

namespace {
using namespace testing::ext;
}

class PropertyNameMapperImplTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_001
 * @tc.desc: Test MapKey with valid letter keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_001, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey("A"), KeyEvent::KEYCODE_A);
    EXPECT_EQ(impl.MapKey("B"), KeyEvent::KEYCODE_B);
    EXPECT_EQ(impl.MapKey("Z"), KeyEvent::KEYCODE_Z);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_002
 * @tc.desc: Test MapKey with valid digit keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_002, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey("0"), KeyEvent::KEYCODE_0);
    EXPECT_EQ(impl.MapKey("1"), KeyEvent::KEYCODE_1);
    EXPECT_EQ(impl.MapKey("9"), KeyEvent::KEYCODE_9);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_003
 * @tc.desc: Test MapKey with valid function keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_003, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey("F1"), KeyEvent::KEYCODE_F1);
    EXPECT_EQ(impl.MapKey("F12"), KeyEvent::KEYCODE_F12);
    EXPECT_EQ(impl.MapKey("F24"), KeyEvent::KEYCODE_F24);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_004
 * @tc.desc: Test MapKey with valid navigation keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_004, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey("ENTER"), KeyEvent::KEYCODE_ENTER);
    EXPECT_EQ(impl.MapKey("SPACE"), KeyEvent::KEYCODE_SPACE);
    EXPECT_EQ(impl.MapKey("TAB"), KeyEvent::KEYCODE_TAB);
    EXPECT_EQ(impl.MapKey("ESCAPE"), KeyEvent::KEYCODE_ESCAPE);
    EXPECT_EQ(impl.MapKey("DPAD_UP"), KeyEvent::KEYCODE_DPAD_UP);
    EXPECT_EQ(impl.MapKey("DPAD_DOWN"), KeyEvent::KEYCODE_DPAD_DOWN);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_005
 * @tc.desc: Test MapKey with valid media keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_005, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey("VOLUME_UP"), KeyEvent::KEYCODE_VOLUME_UP);
    EXPECT_EQ(impl.MapKey("VOLUME_DOWN"), KeyEvent::KEYCODE_VOLUME_DOWN);
    EXPECT_EQ(impl.MapKey("MEDIA_PLAY_PAUSE"), KeyEvent::KEYCODE_MEDIA_PLAY_PAUSE);
    EXPECT_EQ(impl.MapKey("MEDIA_NEXT"), KeyEvent::KEYCODE_MEDIA_NEXT);
    EXPECT_EQ(impl.MapKey("MEDIA_PREVIOUS"), KeyEvent::KEYCODE_MEDIA_PREVIOUS);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_006
 * @tc.desc: Test MapKey with valid modifier keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_006, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey("SHIFT_LEFT"), KeyEvent::KEYCODE_SHIFT_LEFT);
    EXPECT_EQ(impl.MapKey("SHIFT_RIGHT"), KeyEvent::KEYCODE_SHIFT_RIGHT);
    EXPECT_EQ(impl.MapKey("CTRL_LEFT"), KeyEvent::KEYCODE_CTRL_LEFT);
    EXPECT_EQ(impl.MapKey("ALT_LEFT"), KeyEvent::KEYCODE_ALT_LEFT);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_007
 * @tc.desc: Test MapKey with valid gamepad keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_007, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey("BUTTON_A"), KeyEvent::KEYCODE_BUTTON_A);
    EXPECT_EQ(impl.MapKey("BUTTON_B"), KeyEvent::KEYCODE_BUTTON_B);
    EXPECT_EQ(impl.MapKey("BUTTON_X"), KeyEvent::KEYCODE_BUTTON_X);
    EXPECT_EQ(impl.MapKey("BUTTON_Y"), KeyEvent::KEYCODE_BUTTON_Y);
    EXPECT_EQ(impl.MapKey("BUTTON_START"), KeyEvent::KEYCODE_BUTTON_START);
    EXPECT_EQ(impl.MapKey("BUTTON_SELECT"), KeyEvent::KEYCODE_BUTTON_SELECT);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_008
 * @tc.desc: Test MapKey with unknown key name returns KEYCODE_UNKNOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_008, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey(""), KeyEvent::KEYCODE_UNKNOWN);
    EXPECT_EQ(impl.MapKey("NONEXISTENT_KEY"), KeyEvent::KEYCODE_UNKNOWN);
    EXPECT_EQ(impl.MapKey("unknown"), KeyEvent::KEYCODE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_009
 * @tc.desc: Test MapKey with special characters returns KEYCODE_UNKNOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_009, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey("A B"), KeyEvent::KEYCODE_UNKNOWN);
    EXPECT_EQ(impl.MapKey("A\tB"), KeyEvent::KEYCODE_UNKNOWN);
    std::string longName(1000, 'X');
    EXPECT_EQ(impl.MapKey(longName), KeyEvent::KEYCODE_UNKNOWN);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_010
 * @tc.desc: Test MapKey with NUMPAD keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_010, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapKey("NUMPAD_0"), KeyEvent::KEYCODE_NUMPAD_0);
    EXPECT_EQ(impl.MapKey("NUMPAD_9"), KeyEvent::KEYCODE_NUMPAD_9);
    EXPECT_EQ(impl.MapKey("NUMPAD_ENTER"), KeyEvent::KEYCODE_NUMPAD_ENTER);
    EXPECT_EQ(impl.MapKey("NUMPAD_ADD"), KeyEvent::KEYCODE_NUMPAD_ADD);
    EXPECT_EQ(impl.MapKey("NUMPAD_SUBTRACT"), KeyEvent::KEYCODE_NUMPAD_SUBTRACT);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapAxis_001
 * @tc.desc: Test MapAxis with valid basic axes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapAxis_001, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapAxis("X"), PointerEvent::AXIS_TYPE_ABS_X);
    EXPECT_EQ(impl.MapAxis("Y"), PointerEvent::AXIS_TYPE_ABS_Y);
    EXPECT_EQ(impl.MapAxis("Z"), PointerEvent::AXIS_TYPE_ABS_Z);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapAxis_002
 * @tc.desc: Test MapAxis with valid rotation axes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapAxis_002, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapAxis("RX"), PointerEvent::AXIS_TYPE_ABS_RX);
    EXPECT_EQ(impl.MapAxis("RY"), PointerEvent::AXIS_TYPE_ABS_RY);
    EXPECT_EQ(impl.MapAxis("RZ"), PointerEvent::AXIS_TYPE_ABS_RZ);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapAxis_003
 * @tc.desc: Test MapAxis with valid HAT axes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapAxis_003, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapAxis("HAT0X"), PointerEvent::AXIS_TYPE_ABS_HAT0X);
    EXPECT_EQ(impl.MapAxis("HAT0Y"), PointerEvent::AXIS_TYPE_ABS_HAT0Y);
    EXPECT_EQ(impl.MapAxis("HAT1X"), PointerEvent::AXIS_TYPE_ABS_HAT1X);
    EXPECT_EQ(impl.MapAxis("HAT1Y"), PointerEvent::AXIS_TYPE_ABS_HAT1Y);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapAxis_004
 * @tc.desc: Test MapAxis with valid throttle/rudder/wheel axes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapAxis_004, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapAxis("THROTTLE"), PointerEvent::AXIS_TYPE_ABS_THROTTLE);
    EXPECT_EQ(impl.MapAxis("RUDDER"), PointerEvent::AXIS_TYPE_ABS_RUDDER);
    EXPECT_EQ(impl.MapAxis("WHEEL"), PointerEvent::AXIS_TYPE_ABS_WHEEL);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapAxis_005
 * @tc.desc: Test MapAxis with special LTRIGGER/RTRIGGER aliases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapAxis_005, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapAxis("LTRIGGER"), PointerEvent::AXIS_TYPE_ABS_BRAKE);
    EXPECT_EQ(impl.MapAxis("RTRIGGER"), PointerEvent::AXIS_TYPE_ABS_GAS);
    EXPECT_EQ(impl.MapAxis("GAS"), PointerEvent::AXIS_TYPE_ABS_GAS);
    EXPECT_EQ(impl.MapAxis("BRAKE"), PointerEvent::AXIS_TYPE_ABS_BRAKE);
}

/**
 * @tc.name: PropertyNameMapperImpl_MapAxis_006
 * @tc.desc: Test MapAxis with unknown axis name returns AXIS_TYPE_UNKNOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapAxis_006, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    EXPECT_EQ(impl.MapAxis(""), PointerEvent::AXIS_TYPE_UNKNOWN);
    EXPECT_EQ(impl.MapAxis("NONEXISTENT_AXIS"), PointerEvent::AXIS_TYPE_UNKNOWN);
    EXPECT_EQ(impl.MapAxis("x"), PointerEvent::AXIS_TYPE_UNKNOWN); // case sensitive
}

/**
 * @tc.name: PropertyNameMapperImpl_CreateInstance_001
 * @tc.desc: Test CreateInstance returns valid pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_CreateInstance_001, TestSize.Level1)
{
    IPropertyNameMapper* mapper = CreateInstance(nullptr);
    ASSERT_NE(mapper, nullptr);
    EXPECT_EQ(mapper->MapKey("A"), KeyEvent::KEYCODE_A);
    EXPECT_EQ(mapper->MapAxis("X"), PointerEvent::AXIS_TYPE_ABS_X);
    DestroyInstance(mapper);
}

/**
 * @tc.name: PropertyNameMapperImpl_CreateInstance_002
 * @tc.desc: Test CreateInstance with non-null env parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_CreateInstance_002, TestSize.Level1)
{
    IPropertyNameMapper* mapper = CreateInstance(reinterpret_cast<IInputServiceContext*>(0x1));
    ASSERT_NE(mapper, nullptr);
    EXPECT_NE(mapper->MapKey("ENTER"), KeyEvent::KEYCODE_UNKNOWN);
    DestroyInstance(mapper);
}

/**
 * @tc.name: PropertyNameMapperImpl_DestroyInstance_001
 * @tc.desc: Test DestroyInstance with nullptr does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_DestroyInstance_001, TestSize.Level1)
{
    DestroyInstance(nullptr);
    IPropertyNameMapper* mapper = CreateInstance(nullptr);
    ASSERT_NE(mapper, nullptr);
    EXPECT_EQ(mapper->MapKey("A"), KeyEvent::KEYCODE_A);
    EXPECT_EQ(mapper->MapAxis("X"), PointerEvent::AXIS_TYPE_ABS_X);
    DestroyInstance(mapper);
}

/**
 * @tc.name: PropertyNameMapperImpl_DestroyInstance_002
 * @tc.desc: Test DestroyInstance with valid instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_DestroyInstance_002, TestSize.Level1)
{
    IPropertyNameMapper* mapper = CreateInstance(nullptr);
    ASSERT_NE(mapper, nullptr);
    DestroyInstance(mapper);
    SUCCEED();
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_Consistency_001
 * @tc.desc: Test MapKey returns consistent results for same input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_Consistency_001, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(impl.MapKey("A"), KeyEvent::KEYCODE_A);
    }
}

/**
 * @tc.name: PropertyNameMapperImpl_MapAxis_Consistency_001
 * @tc.desc: Test MapAxis returns consistent results for same input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapAxis_Consistency_001, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(impl.MapAxis("X"), PointerEvent::AXIS_TYPE_ABS_X);
    }
}

/**
 * @tc.name: PropertyNameMapperImpl_MapKey_AllLetters_001
 * @tc.desc: Test MapKey with all 26 letters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PropertyNameMapperImplTest, PropertyNameMapperImpl_MapKey_AllLetters_001, TestSize.Level1)
{
    PropertyNameMapperImpl impl;
    const std::vector<std::pair<std::string, int32_t>> letterKeys = {
        {"A", KeyEvent::KEYCODE_A}, {"B", KeyEvent::KEYCODE_B}, {"C", KeyEvent::KEYCODE_C},
        {"D", KeyEvent::KEYCODE_D}, {"E", KeyEvent::KEYCODE_E}, {"F", KeyEvent::KEYCODE_F},
        {"G", KeyEvent::KEYCODE_G}, {"H", KeyEvent::KEYCODE_H}, {"I", KeyEvent::KEYCODE_I},
        {"J", KeyEvent::KEYCODE_J}, {"K", KeyEvent::KEYCODE_K}, {"L", KeyEvent::KEYCODE_L},
        {"M", KeyEvent::KEYCODE_M}, {"N", KeyEvent::KEYCODE_N}, {"O", KeyEvent::KEYCODE_O},
        {"P", KeyEvent::KEYCODE_P}, {"Q", KeyEvent::KEYCODE_Q}, {"R", KeyEvent::KEYCODE_R},
        {"S", KeyEvent::KEYCODE_S}, {"T", KeyEvent::KEYCODE_T}, {"U", KeyEvent::KEYCODE_U},
        {"V", KeyEvent::KEYCODE_V}, {"W", KeyEvent::KEYCODE_W}, {"X", KeyEvent::KEYCODE_X},
        {"Y", KeyEvent::KEYCODE_Y}, {"Z", KeyEvent::KEYCODE_Z},
    };
    for (const auto& [name, expected] : letterKeys) {
        EXPECT_EQ(impl.MapKey(name), expected) << "Failed for key: " << name;
    }
}
} // namespace MMI
} // namespace OHOS
