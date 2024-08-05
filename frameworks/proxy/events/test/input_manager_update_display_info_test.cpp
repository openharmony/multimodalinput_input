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
#include <semaphore.h>
#include <random>
#include <gtest/gtest.h>

#include "pixel_map.h"

#include "mmi_log.h"
#include "input_manager.h"
#include "system_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "UpdateDisplayInfoTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t TIME_MS = 20;
constexpr int32_t DISPLAYINFO_WIDTH = 2;
constexpr int32_t DISPLAYINFO_HEIGHT = 2;
constexpr int32_t DISPLAYINFO_DPI = 240;
} // namespace

class InputManagerUpdateDisplayInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    std::shared_ptr<OHOS::Media::PixelMap> MatrixToPixelmap(const std::vector<std::vector<uint32_t>> &windowMask) const;
    std::vector<std::vector<uint32_t>> CreateMatrix(int32_t width, int32_t height) const;
    void CheckMaskDisplayPoint(OHOS::Media::PixelMap *pixelMap, int32_t displayX, int32_t displayY) const;
    DisplayInfo CreateDisplayInfo(int32_t id) const;
};

std::shared_ptr<OHOS::Media::PixelMap> InputManagerUpdateDisplayInfoTest::MatrixToPixelmap(
    const std::vector<std::vector<uint32_t>> &windowMask) const
{
    MMI_HILOGD("MatrixToPixelmap--enter");
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    uint32_t maskHeight = windowMask.size();
    if (maskHeight < 1) {
        MMI_HILOGE("Filed to create a pixelMap, err maskHeight %{public}d <1", maskHeight);
        return pixelMap;
    }
    uint32_t maskWidth = windowMask[0].size();
    if (maskHeight < 1) {
        MMI_HILOGE("Filed to create a pixelMap, err maskWidth %{public}d <1", maskWidth);
        return pixelMap;
    }
    OHOS::Media::InitializationOptions ops;
    ops.size.width = maskWidth;
    ops.size.height = maskHeight;
    ops.pixelFormat = OHOS::Media::PixelFormat::RGBA_8888;
    ops.alphaType = OHOS::Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    ops.scaleMode = OHOS::Media::ScaleMode::FIT_TARGET_SIZE;
    uint32_t length = maskHeight * maskWidth;
    uint32_t *data = new (std::nothrow) uint32_t[length];
    CHKPP(data);
    for (uint32_t i = 0; i < maskHeight; i++) {
        if (windowMask[i].size() != maskWidth) {
            MMI_HILOGE(
                "Filed to create a pixelMap,row:%{public}d curSize:%{public}zu not equal frist row size:%{public}d",
                i, windowMask[i].size(), maskWidth);
            return nullptr;
        }
        for (uint32_t j = 0; j < maskWidth; j++) {
            uint32_t idx = i * maskWidth + j;
            data[idx] = windowMask[i][j];
        }
    }
    pixelMap = OHOS::Media::PixelMap::Create(data, length, ops);
    delete[] data;
    data = nullptr;
    CHKPP(pixelMap);
    MMI_HILOGD("MatrixToPixelmap--end");
    return pixelMap;
}

std::vector<std::vector<uint32_t>> InputManagerUpdateDisplayInfoTest::CreateMatrix(int32_t width, int32_t height) const
{
    MMI_HILOGD("CreateMatrix--enter");
    if (width < 1) {
        MMI_HILOGE("Filed to create a Matrix, err width %{public}d <1", width);
        return std::vector<std::vector<uint32_t>>();
    }
    if (height < 1) {
        MMI_HILOGE("Filed to create a Matrix, err height %{public}d <1", height);
        return std::vector<std::vector<uint32_t>>();
    }
    std::vector<std::vector<uint32_t>> matrix(height, std::vector<uint32_t>(width, 0));
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 1);
    for (int32_t i = 0; i < height; i++) {
        for (int32_t j = 0; j < width; j++) {
            matrix[i][j] = dist(gen);
        }
    }
    MMI_HILOGD("CreateMatrix--end");
    return matrix;
}

void InputManagerUpdateDisplayInfoTest::CheckMaskDisplayPoint(OHOS::Media::PixelMap *pixelMap, int32_t displayX,
    int32_t displayY) const
{
    CHKPV(pixelMap);
    uint32_t dst = 0;
    OHOS::Media::Position pos { displayX, displayY };
    pixelMap->ReadPixel(pos, dst);
    if (dst == 0) {
        MMI_HILOGI("It's transparent area, dst:%{public}d", dst);
    } else {
        MMI_HILOGI("It's non-transparent area, dst:%{public}d", dst);
    }
}

DisplayInfo InputManagerUpdateDisplayInfoTest::CreateDisplayInfo(int32_t id) const
{
    DisplayInfo displayinfo;
    displayinfo.id = id;
    displayinfo.x = 1;
    displayinfo.y = 1;
    displayinfo.width = DISPLAYINFO_WIDTH;
    displayinfo.height = DISPLAYINFO_HEIGHT;
    displayinfo.dpi = DISPLAYINFO_DPI;
    displayinfo.name = "pp";
    displayinfo.uniq = "pp";
    displayinfo.direction = DIRECTION0;
    return displayinfo;
}

/**
 * @tc.name: InputManagerTest_UpdateDisplayInfoShaped_001
 * @tc.desc: Update shaped window information for 1 display and 1 window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerUpdateDisplayInfoTest, InputManagerTest_UpdateDisplayInfoShaped_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::vector<uint32_t>> maskMatrix = { { 1, 1, 1, 1, 1, 1 }, { 0, 0, 1, 1, 0, 0 }, { 0, 0, 1, 1, 0, 0 },
        { 0, 0, 1, 1, 0, 0 }, { 0, 0, 1, 1, 0, 0 }, { 0, 0, 0, 0, 0, 0 } };
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = MatrixToPixelmap(maskMatrix);
    ASSERT_NE(pixelMap, nullptr);
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 1;
    displayGroupInfo.width = 1000;
    displayGroupInfo.height = 2000;
    DisplayInfo displayinfo = CreateDisplayInfo(0);
    displayGroupInfo.displaysInfo.push_back(displayinfo);
    WindowInfo info;
    info.agentWindowId = 1;
    info.id = 1;
    info.pid = 1;
    info.uid = 1;
    info.area = { 1, 1, 1, 1 };
    info.defaultHotAreas = { info.area };
    info.pointerHotAreas = { info.area };
    info.pointerChangeAreas = { 16, 5, 16, 5, 16, 5, 16, 5 };
    info.transform = { 1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f };
    info.agentWindowId = 1;
    info.flags = 0;
    info.displayId = 0;
    info.pixelMap = pixelMap.get();
    displayGroupInfo.windowsInfo.push_back(info);
    ASSERT_NO_FATAL_FAILURE(InputManager::GetInstance()->UpdateDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputManagerTest_UpdateDisplayInfoShaped_002
 * @tc.desc: Update shaped window information, for 1 display and 1 window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerUpdateDisplayInfoTest, InputManagerTest_UpdateDisplayInfoShaped_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t height = 10;
    ASSERT_GE(height, 1);
    int32_t width = 20;
    ASSERT_GE(width, 1);
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    pixelMap = MatrixToPixelmap(CreateMatrix(width, height));
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_MS));
    ASSERT_NE(pixelMap, nullptr);
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 1;
    displayGroupInfo.width = 1000;
    displayGroupInfo.height = 2000;
    DisplayInfo displayinfo = CreateDisplayInfo(0);
    displayGroupInfo.displaysInfo.push_back(displayinfo);
    WindowInfo info;
    info.id = 1;
    info.pid = 1;
    info.uid = 1;
    info.area = { 1, 1, 1, 1 };
    info.defaultHotAreas = { info.area };
    info.pointerHotAreas = { info.area };
    info.pointerChangeAreas = { 16, 5, 16, 5, 16, 5, 16, 5 };
    info.transform = { 1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f };
    info.agentWindowId = 1;
    info.flags = 0;
    info.displayId = 0;
    info.pixelMap = pixelMap.get();
    displayGroupInfo.windowsInfo.push_back(info);
    int32_t displayX = width / 2;
    int32_t displayY = height / 2;
    CheckMaskDisplayPoint(pixelMap.get(), displayX, displayY);
    ASSERT_NO_FATAL_FAILURE(InputManager::GetInstance()->UpdateDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputManagerTest_UpdateDisplayInfoShaped_003
 * @tc.desc: Update shaped window information, for 1 display and max-windows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerUpdateDisplayInfoTest, InputManagerTest_UpdateDisplayInfoShaped_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 0;
    displayGroupInfo.width = 1000;
    displayGroupInfo.height = 2000;
    DisplayInfo displayinfo = CreateDisplayInfo(0);
    displayinfo.direction = DIRECTION0;
    displayinfo.displayMode = DisplayMode::FULL;
    displayGroupInfo.displaysInfo.push_back(displayinfo);
    std::vector<std::vector<int32_t>> maskSizeMatrix = { { 100, 300 }, { 30, 30 }, { 50, 50 }, { 80, 80 }, { 10, 8 },
        { 5, 20 },    { 6, 10 },  { 30, 30 }, { 20, 30 }, { 40, 10 } };
    std::vector<std::shared_ptr<OHOS::Media::PixelMap>> vecPixelMap;
    for (uint32_t i = 0; i < maskSizeMatrix.size(); i++) {
        ASSERT_EQ(maskSizeMatrix[i].size(), 2);
        ASSERT_GE(maskSizeMatrix[i][0], 2);
        ASSERT_GE(maskSizeMatrix[i][1], 2);
        MMI_HILOGD("Begin=========> i=%{public}d; width=%{public}d height=%{public}d", i, maskSizeMatrix[i][0],
            maskSizeMatrix[i][1]);
        WindowInfo info;
        info.id = i + 1;
        info.pid = 1;
        info.uid = 1;
        info.area = { 1, 1, 1, 1 };
        info.defaultHotAreas = { info.area };
        info.pointerHotAreas = { info.area };
        info.pointerChangeAreas = { 16, 5, 16, 5, 16, 5, 16, 5 };
        info.transform = { 1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f };
        info.agentWindowId = 1;
        info.flags = 0;
        info.displayId = 0;
        info.zOrder = static_cast<float>(maskSizeMatrix.size() - i);
        std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
        MMI_HILOGD("CreateMatrix begin ");
        auto maskMatrix = CreateMatrix(maskSizeMatrix[i][1], maskSizeMatrix[i][0]);
        MMI_HILOGD("CreateMatrix end ");
        pixelMap = MatrixToPixelmap(maskMatrix);
        MMI_HILOGD("MatrixToPixelmap end ");
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_MS));
        ASSERT_NE(pixelMap, nullptr);
        CHKPV(pixelMap);
        vecPixelMap.push_back(pixelMap);
        info.pixelMap = pixelMap.get();
        displayGroupInfo.windowsInfo.push_back(info);
        int32_t displayX = maskSizeMatrix[i][0] / 2;
        int32_t displayY = maskSizeMatrix[i][1] / 2;
        CheckMaskDisplayPoint(pixelMap.get(), displayX, displayY);
    }
    ASSERT_NO_FATAL_FAILURE(InputManager::GetInstance()->UpdateDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputManagerTest_UpdateDisplayInfoShaped_004
 * @tc.desc: Update shaped window information, for 1 display and 1 window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerUpdateDisplayInfoTest, InputManagerTest_UpdateDisplayInfoShaped_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 1;
    displayGroupInfo.width = 1000;
    displayGroupInfo.height = 2000;
    std::vector<std::shared_ptr<OHOS::Media::PixelMap>> vecPixelMap;
    std::vector<std::vector<int32_t>> maskSizeMatrix = { { 800, 600 }, { 1024, 1024 } };
    for (uint32_t i = 0; i < maskSizeMatrix.size(); i++) {
        DisplayInfo displayinfo = CreateDisplayInfo(i);
        displayGroupInfo.displaysInfo.push_back(displayinfo);
    }
    for (uint32_t i = 0; i < maskSizeMatrix.size(); i++) { // 2 widonw for 2 display
        ASSERT_EQ(maskSizeMatrix[i].size(), 2);
        ASSERT_GE(maskSizeMatrix[i][0], 2);
        ASSERT_GE(maskSizeMatrix[i][1], 2);
        WindowInfo info;
        info.id = 1;
        info.pid = 1;
        info.uid = 1;
        info.area = { 1, 1, 1, 1 };
        info.defaultHotAreas = { info.area };
        info.agentWindowId = 1;
        info.flags = 0;
        info.displayId = i;
        std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
        auto maskMatrix = CreateMatrix(maskSizeMatrix[i][1], maskSizeMatrix[i][0]);
        pixelMap = MatrixToPixelmap(maskMatrix);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_MS));
        ASSERT_NE(pixelMap, nullptr);
        CHKPV(pixelMap);
        vecPixelMap.push_back(pixelMap);
        info.pixelMap = pixelMap.get();
        displayGroupInfo.windowsInfo.push_back(info);
        int32_t displayX = maskSizeMatrix[i][1] / 2;
        int32_t displayY = maskSizeMatrix[i][0] / 2;
        CheckMaskDisplayPoint(pixelMap.get(), displayX, displayY);
    }
    ASSERT_NO_FATAL_FAILURE(InputManager::GetInstance()->UpdateDisplayInfo(displayGroupInfo));
}
} // namespace MMI
} // namespace OHOS
