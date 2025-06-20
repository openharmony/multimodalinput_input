/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "pointer_style.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerStyleTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class PointerStyleTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: PointerStyleTest_CursorPixelMap_Marshalling_001
 * @tc.desc: Test Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerStyleTest, PointerStyleTest_CursorPixelMap_Marshalling_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorPixelMap cMap;
    Parcel out;
    cMap.pixelMap = nullptr;
    bool ret = cMap.Marshalling(out);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: PointerStyleTest_CursorPixelMap_ReadFromParcel_001
 * @tc.desc: Test ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerStyleTest, PointerStyleTest_CursorPixelMap_ReadFromParcel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorPixelMap cMap;
    Parcel out;
    cMap.pixelMap = nullptr;
    bool ret = cMap.ReadFromParcel(out);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: PointerStyleTest_CursorPixelMap_Unmarshalling_001
 * @tc.desc: Test Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerStyleTest, PointerStyleTest_CursorPixelMap_Unmarshalling_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorPixelMap cMap;
    Parcel out;
    cMap.pixelMap = nullptr;
    auto ret = cMap.Unmarshalling(out);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: PointerStyleTest_CursorOptionsParcel_ReadFromParcel_001
 * @tc.desc: Test ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerStyleTest, PointerStyleTest_CursorOptionsParcel_ReadFromParcel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorOptionsParcel cOpt;
    Parcel out;
    cOpt.followSystem = true;
    bool ret = cOpt.ReadFromParcel(out);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: PointerStyleTest_CursorOptionsParcel_Unmarshalling_001
 * @tc.desc: Test Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerStyleTest, PointerStyleTest_CursorOptionsParcel_Unmarshalling_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorOptionsParcel cOpt;
    Parcel out;
    cOpt.followSystem = true;
    auto ret = cOpt.Unmarshalling(out);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: PointerStyleTest_CustomCursorParcel_ReadFromParcel_001
 * @tc.desc: Test ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerStyleTest, PointerStyleTest_CustomCursorParcel_ReadFromParcel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CustomCursorParcel cusCor;
    cusCor.pixelMap = nullptr;
    cusCor.focusX = 1;
    cusCor.focusY = 1;
    Parcel in;
    bool ret = cusCor.ReadFromParcel(in);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: PointerStyleTest_CustomCursorParcel_Unmarshalling_001
 * @tc.desc: Test Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerStyleTest, PointerStyleTest_CustomCursorParcel_Unmarshalling_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CustomCursorParcel cusCor;
    cusCor.pixelMap = nullptr;
    cusCor.focusX = 1;
    cusCor.focusY = 1;
    Parcel out;
    auto ret = cusCor.Unmarshalling(out);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: PointerStyleTest_PointerStyle_ReadFromParcel_001
 * @tc.desc: Test ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerStyleTest, PointerStyleTest_PointerStyle_ReadFromParcel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerStyle pointerStyle;
    Parcel parcel;
    ASSERT_NO_FATAL_FAILURE(pointerStyle.ReadFromParcel(parcel));
}

/**
 * @tc.name: PointerStyleTest_PointerStyle_Unmarshalling_001
 * @tc.desc: Test Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerStyleTest, PointerStyleTest_PointerStyle_Unmarshalling_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerStyle pointerStyle;
    Parcel parcel;
    ASSERT_NO_FATAL_FAILURE(pointerStyle.Unmarshalling(parcel));
}
} // namespace MMI
} // namespace OHOS