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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "oh_input_manager.h"
#include "mmi_log.h"
#include "mock.h"
#include "pixel_map.h"
#include "image/pixelmap_native.h"
#include "pixelmap_native_impl.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "OHInputManagerEXTest"
struct Input_CursorInfo {
    bool visible { false };
    Input_PointerStyle style { DEFAULT };
    int32_t sizeLevel { 0 };
    uint32_t color { 0 };
};

struct Input_MouseEvent {
    int32_t action;
    int32_t displayX;
    int32_t displayY;
    int32_t globalX { INT32_MAX  };
    int32_t globalY { INT32_MAX  };
    int32_t button { -1 };
    int32_t axisType { -1 };
    float axisValue { 0.0f };
    int64_t actionTime { -1 };
    int32_t windowId { -1 };
    int32_t displayId { -1 };
    Input_CursorInfo cursorInfo;
};

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using ::testing::_;
using ::testing::Return;
} // namespace

class OHInputManagerEXTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() {}
    void TearDown() {}

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void OHInputManagerEXTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}

void OHInputManagerEXTest::TearDownTestCase(void)
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}


/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_001
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_001, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    
    EXPECT_CALL(*messageParcelMock_, GetPointerLocation(_, _, _))
        .WillOnce(Return(INPUT_DEVICE_NO_POINTER));
    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_DEVICE_NO_POINTER);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_002
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_002, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    
    EXPECT_CALL(*messageParcelMock_, GetPointerLocation(_, _, _))
        .WillOnce(Return(INPUT_APP_NOT_FOCUSED));
    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_APP_NOT_FOCUSED);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_003
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_003, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    
    EXPECT_CALL(*messageParcelMock_, GetPointerLocation(_, _, _))
        .WillOnce(Return(INPUT_SERVICE_EXCEPTION));
    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_SERVICE_EXCEPTION);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_004
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_004, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    
    EXPECT_CALL(*messageParcelMock_, GetPointerLocation(_, _, _))
        .WillOnce(Return(INPUT_SUCCESS));
    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_SUCCESS);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_005
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_005, TestSize.Level1)
{
    double displayX = 0.0;
    double displayY = 0.0;
    
    Input_Result result = OH_Input_GetPointerLocation(nullptr, &displayX, &displayY);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_006
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_006, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayY = 0.0;
    
    Input_Result result = OH_Input_GetPointerLocation(&displayId, nullptr, &displayY);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name:  OHInputManagerEXTest_GetPointerLocation_007
 * @tc.desc: Get Pointer location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_GetPointerLocation_007, TestSize.Level1)
{
    int32_t displayId = 0;
    double displayX = 0.0;

    Input_Result result = OH_Input_GetPointerLocation(&displayId, &displayX, nullptr);
    EXPECT_EQ(result, INPUT_PARAMETER_ERROR);
}

/**
 * @tc.name: OHInputManagerEXTest_OH_Input_GetCursorInfo_001
 * @tc.desc: Test OH_Input_GetCursorInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OHInputManagerEXTest, OHInputManagerEXTest_OH_Input_GetCursorInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto ret = OH_Input_GetCursorInfo(nullptr, nullptr);
    ASSERT_EQ(ret, INPUT_PARAMETER_ERROR);
    EXPECT_CALL(*messageParcelMock_, GetCurrentCursorInfo(_, _))
        .WillOnce(Return(RET_ERR));
    Input_CursorInfo cursorInfo;
    ret = OH_Input_GetCursorInfo(&cursorInfo, nullptr);
    ASSERT_EQ(ret, INPUT_SERVICE_EXCEPTION);

    EXPECT_CALL(*messageParcelMock_, GetCurrentCursorInfo(_, _))
        .WillOnce(Return(-2));
    ret = OH_Input_GetCursorInfo(&cursorInfo, nullptr);
    ASSERT_EQ(ret, INPUT_SUCCESS);
    ASSERT_EQ(cursorInfo.visible, false);

    EXPECT_CALL(*messageParcelMock_, GetCurrentCursorInfo(_, _))
        .WillOnce(testing::DoAll(testing::SetArgReferee<0>(false), Return(RET_OK)));
    ret = OH_Input_GetCursorInfo(&cursorInfo, nullptr);
    ASSERT_EQ(ret, INPUT_SUCCESS);

    EXPECT_CALL(*messageParcelMock_, GetCurrentCursorInfo(_, _))
        .Times(2)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<0>(true), Return(RET_OK)));
    ret = OH_Input_GetCursorInfo(&cursorInfo, nullptr);
    ASSERT_EQ(ret, INPUT_SUCCESS);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    OH_PixelmapNative* pixelmapNative = new OH_PixelmapNative(pixelMap);
    ret = OH_Input_GetCursorInfo(&cursorInfo, &pixelmapNative);
    ASSERT_EQ(ret, INPUT_SUCCESS);

    PointerStyle pointerStyle;
    pointerStyle.id = Input_PointerStyle::DEVELOPER_DEFINED_ICON;
    EXPECT_CALL(*messageParcelMock_, GetCurrentCursorInfo(_, _))
        .Times(2)
        .WillRepeatedly(testing::DoAll(testing::SetArgReferee<0>(true), testing::SetArgReferee<1>(pointerStyle),
            Return(RET_OK)));
    EXPECT_CALL(*messageParcelMock_, GetUserDefinedCursorPixelMap(_))
        .WillOnce(Return(RET_ERR));
    ret = OH_Input_GetCursorInfo(&cursorInfo, &pixelmapNative);
    ASSERT_EQ(ret, INPUT_SERVICE_EXCEPTION);

    EXPECT_CALL(*messageParcelMock_, GetUserDefinedCursorPixelMap(_))
        .WillOnce(Return(RET_OK));
    ret = OH_Input_GetCursorInfo(&cursorInfo, &pixelmapNative);
    ASSERT_EQ(ret, INPUT_SUCCESS);
    OH_PixelmapNative_Destroy(&pixelmapNative);
}
} // namespace MMI
} // namespace OHOS