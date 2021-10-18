/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "mouse_event.h"


namespace {
using namespace testing::ext;
using namespace std;
using namespace OHOS;

class MouseEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

MouseEvent mouseEvent;
HWTEST_F(MouseEventTest, Initialize_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t actionId = 1;
    int32_t actionButton = 1;
    int32_t pressedButtons = 1;
    MmiPoint mmiPoint(1, 1);
    float xOffset = 1;
    float yOffset = 1;
    float cursorDelta = 1;
    float scrollingDelta = 1;
    int32_t highLevelEvent = 1;
    std::string strUuid = "1";
    int32_t sourceType = 1;
    int32_t occurredTime = 1;
    std::string deviceId = "1";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};

    mouseEvent.Initialize(windowId, actionId, actionButton, pressedButtons, mmiPoint,
                          xOffset, yOffset, cursorDelta, scrollingDelta,
                          highLevelEvent, strUuid, sourceType, occurredTime,
                          deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
}

HWTEST_F(MouseEventTest, Initialize_002, TestSize.Level1)
{
    MmiPoint mmiPoint(1, 1);
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(1, 1, 1, 1, mmiPoint, 1, 1, 1, 1, 1, "1", 1, 1, "1", 1, true, deviceUdevTags,
                             eventJoyStickInfo);
}

HWTEST_F(MouseEventTest, Initialize_003, TestSize.Level1)
{
    MmiPoint mmiPoint(1, 1);
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(1, 1, 1, 1, mmiPoint, 1, 1, 1, 1, 1, "1", 1, 1, "1", 1, false, deviceUdevTags,
                             eventJoyStickInfo);
}

HWTEST_F(MouseEventTest, Initialize_004, TestSize.Level1)
{
    MouseEvent mouseEventTmp;
    mouseEventTmp.Initialize(mouseEvent);
}

HWTEST_F(MouseEventTest, Initialize_005, TestSize.Level1)
{
    MouseEvent mouseEvent2;
    MouseEvent mouseEventTmp;
    mouseEventTmp.Initialize(mouseEvent2);
}

HWTEST_F(MouseEventTest, GetAction, TestSize.Level1)
{
    int32_t retResult = mouseEvent.GetAction();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(MouseEventTest, GetActionButton, TestSize.Level1)
{
    int32_t retResult = mouseEvent.GetActionButton();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(MouseEventTest, GetPressedButtons, TestSize.Level1)
{
    int32_t retResult = mouseEvent.GetPressedButtons();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(MouseEventTest, GetCursor_001, TestSize.Level1)
{
    MmiPoint tmpMultiPoint = mouseEvent.GetCursor();
    EXPECT_EQ(1, tmpMultiPoint.GetX());
}

HWTEST_F(MouseEventTest, GetCursor_002, TestSize.Level1)
{
    MmiPoint tmpMultiPoint = mouseEvent.GetCursor();
    EXPECT_EQ(1, tmpMultiPoint.GetY());
}

HWTEST_F(MouseEventTest, SetCursorOffset, TestSize.Level1)
{
    mouseEvent.SetCursorOffset(3, 4);
}

HWTEST_F(MouseEventTest, GetXOffset, TestSize.Level1)
{
    mouseEvent.SetCursorOffset(3, 4);
    float retResult = mouseEvent.GetXOffset();
    EXPECT_EQ(3, retResult);
}

HWTEST_F(MouseEventTest, GetYOffset, TestSize.Level1)
{
    mouseEvent.SetCursorOffset(3, 4);
    float retResult = mouseEvent.GetYOffset();
    EXPECT_EQ(4, retResult);
}

HWTEST_F(MouseEventTest, GetCursorDelta_001, TestSize.Level1)
{
    float retResult = mouseEvent.GetCursorDelta(0);
    EXPECT_EQ(1, retResult);
}

HWTEST_F(MouseEventTest, GetCursorDelta_002, TestSize.Level1)
{
    float retResult = mouseEvent.GetCursorDelta(1);
    EXPECT_EQ(1, retResult);
}

HWTEST_F(MouseEventTest, GetScrollingDelta_001, TestSize.Level1)
{
    float retResult = mouseEvent.GetScrollingDelta(0);
    EXPECT_EQ(1, retResult);
}

HWTEST_F(MouseEventTest, GetScrollingDelta_002, TestSize.Level1)
{
    float retResult = mouseEvent.GetScrollingDelta(1);
    EXPECT_EQ(1, retResult);
}

HWTEST_F(MouseEventTest, Initialize_L, TestSize.Level1)
{
    MmiPoint mmiPoint(7, 7);
    std::string strUuid = "777";
    std::string deviceId = "777";
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEvent.Initialize(7, 7, 7, 7, mmiPoint, 7, 7, 7, 7, 7, strUuid, 7, 7, deviceId, 7, false, deviceUdevTags,
                          eventJoyStickInfo);
}

HWTEST_F(MouseEventTest, GetAction_L, TestSize.Level1)
{
    int32_t retResult = mouseEvent.GetAction();
    EXPECT_TRUE(retResult == 7);
}

HWTEST_F(MouseEventTest, GetActionButton_L, TestSize.Level1)
{
    int32_t retResult = mouseEvent.GetActionButton();
    EXPECT_TRUE(retResult == 7);
}

HWTEST_F(MouseEventTest, GetPressedButtons_L, TestSize.Level1)
{
    int32_t retResult = mouseEvent.GetPressedButtons();
    EXPECT_TRUE(retResult == 7);
}

HWTEST_F(MouseEventTest, GetCursor_L_001, TestSize.Level1)
{
    MmiPoint mmiPoint = mouseEvent.GetCursor();
    EXPECT_EQ(7, mmiPoint.GetX());
}

HWTEST_F(MouseEventTest, GetCursor_L_002, TestSize.Level1)
{
    MmiPoint mmiPoint = mouseEvent.GetCursor();
    EXPECT_EQ(7, mmiPoint.GetY());
}

HWTEST_F(MouseEventTest, GetCursorDelta_L_001, TestSize.Level1)
{
    float retResult = mouseEvent.GetCursorDelta(0);
    EXPECT_EQ(7, retResult);
}

HWTEST_F(MouseEventTest, GetCursorDelta_L_002, TestSize.Level1)
{
    float retResult = mouseEvent.GetCursorDelta(1);
    EXPECT_EQ(7, retResult);
}

HWTEST_F(MouseEventTest, GetScrollingDelta_L_001, TestSize.Level1)
{
    float retResult = mouseEvent.GetScrollingDelta(0);
    EXPECT_EQ(7, retResult);
}

HWTEST_F(MouseEventTest, GetScrollingDelta_L_002, TestSize.Level1)
{
    float retResult = mouseEvent.GetScrollingDelta(1);
    EXPECT_EQ(7, retResult);
}

HWTEST_F(MouseEventTest, GetAction_TMP_001, TestSize.Level1)
{
    int32_t actionId = 65535;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(93, actionId, 93, 93, {93, 93, 93}, 93, 93, 93, 93, 93,
                             "939393", 93, 93, "939393", 93, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetAction();
    EXPECT_EQ(retResult, actionId);
}

HWTEST_F(MouseEventTest, GetAction_TMP_002, TestSize.Level1)
{
    int32_t actionId = static_cast<int32_t>('i');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(12, actionId, 12, 12, {12, 12, 12}, 12, 12, 12, 12, 12,
                             "121212", 12, 12, "121212", 12, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetAction();
    EXPECT_EQ(retResult, actionId);
}

HWTEST_F(MouseEventTest, GetAction_TMP_003, TestSize.Level1)
{
    int32_t actionId = static_cast<int32_t>('i') + static_cast<int32_t>('k');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(6, actionId, 6, 6, {6, 6, 6}, 6, 6, 6, 6, 6, "666", 6, 6, "666", 6, false,
                             deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetAction();
    EXPECT_EQ(retResult, actionId);
}

HWTEST_F(MouseEventTest, GetAction_TMP_004, TestSize.Level1)
{
    int32_t actionId = -65535;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(55, actionId, 55, 55, {55, 55, 55}, 55, 55, 55, 55, 55,
                             "555555", 55, 55, "555555", 55, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetAction();
    EXPECT_EQ(retResult, actionId);
}

HWTEST_F(MouseEventTest, GetActionButton_TMP_001, TestSize.Level1)
{
    int32_t actionId = 143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(25, 25, actionId, 25, {25, 25, 25}, 25, 25, 25, 25, 25,
                             "252525", 25, 25, "252525", 25, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetActionButton();
    EXPECT_EQ(retResult, actionId);
}

HWTEST_F(MouseEventTest, GetActionButton_TMP_002, TestSize.Level1)
{
    int32_t actionId = static_cast<int32_t>('i');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(22, 22, actionId, 22, {22, 22, 22}, 22, 22, 22, 22, 22,
                             "222222", 22, 22, "222222", 22, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetActionButton();
    EXPECT_EQ(retResult, actionId);
}

HWTEST_F(MouseEventTest, GetActionButton_TMP_003, TestSize.Level1)
{
    int32_t actionId = static_cast<int32_t>('i') + static_cast<int32_t>('k');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(14, 14, actionId, 14, {14, 14, 14}, 14, 14, 14, 14, 14,
                             "141414", 14, 14, "141414", 14, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetActionButton();
    EXPECT_EQ(retResult, actionId);
}

HWTEST_F(MouseEventTest, GetActionButton_TMP_004, TestSize.Level1)
{
    int32_t actionId = -143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(31, 31, actionId, 31, {31, 31, 31}, 31, 31, 31, 31, 31,
                             "313131", 31, 31, "313131", 31, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetActionButton();
    EXPECT_EQ(retResult, actionId);
}

HWTEST_F(MouseEventTest, GetPressedButtons_TMP_001, TestSize.Level1)
{
    int32_t pressesId = 143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(25, 25, 25, pressesId, {25, 25, 25}, 25, 25, 25, 25, 25,
                             "252525", 25, 25, "252525", 25, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetPressedButtons();
    EXPECT_EQ(retResult, pressesId);
}

HWTEST_F(MouseEventTest, GetPressedButtons_TMP_002, TestSize.Level1)
{
    int32_t pressesId = static_cast<int32_t>('i');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(22, 22, 22, pressesId, {22, 22, 22}, 22, 22, 22, 22, 22,
                             "222222", 22, 22, "222222", 22, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetPressedButtons();
    EXPECT_EQ(retResult, pressesId);
}

HWTEST_F(MouseEventTest, GetPressedButtons_TMP_003, TestSize.Level1)
{
    int32_t pressesId = static_cast<int32_t>('i') + static_cast<int32_t>('k');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(14, 14, 14, pressesId, {14, 14, 14}, 14, 14, 14, 14, 14,
                             "141414", 14, 14, "141414", 14, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetPressedButtons();
    EXPECT_EQ(retResult, pressesId);
}

HWTEST_F(MouseEventTest, GetPressedButtons_TMP_004, TestSize.Level1)
{
    int32_t pressesId = -143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(31, 31, 31, pressesId, {31, 31, 31}, 31, 31, 31, 31, 31,
                             "313131", 31, 31, "313131", 31, false, deviceUdevTags, eventJoyStickInfo);
    int32_t retResult = mouseEventTmp.GetPressedButtons();
    EXPECT_EQ(retResult, pressesId);
}

HWTEST_F(MouseEventTest, GetCursor_TMP_001, TestSize.Level1)
{
    MmiPoint mmPoint(36, 26, 54);
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(25, 25, 25, 25, mmPoint, 25, 25, 25, 25, 25,
                             "252525", 25, 25, "252525", 25, false, deviceUdevTags, eventJoyStickInfo);
    MmiPoint retResult = mouseEventTmp.GetCursor();
    EXPECT_EQ(retResult.GetX(), mmPoint.GetX());
    EXPECT_EQ(retResult.GetY(), mmPoint.GetY());
    EXPECT_EQ(retResult.GetZ(), mmPoint.GetZ());
}

HWTEST_F(MouseEventTest, GetCursor_TMP_002, TestSize.Level1)
{
    MmiPoint mmPoint(36, 26, 54);
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(22, 22, 22, 22, mmPoint, 22, 22, 22, 22, 22,
                             "222222", 22, 22, "222222", 22, false, deviceUdevTags, eventJoyStickInfo);
    MmiPoint retResult = mouseEventTmp.GetCursor();
    EXPECT_EQ(retResult.GetX(), mmPoint.GetX());
    EXPECT_EQ(retResult.GetY(), mmPoint.GetY());
    EXPECT_EQ(retResult.GetZ(), mmPoint.GetZ());
}

HWTEST_F(MouseEventTest, GetCursor_TMP_003, TestSize.Level1)
{
    MmiPoint mmiPoint(36, 26, 54);
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(14, 14, 14, 14, mmiPoint, 14, 14, 14, 14, 14,
                             "141414", 14, 14, "141414", 14, false, deviceUdevTags, eventJoyStickInfo);
    MmiPoint retResult = mouseEventTmp.GetCursor();
    EXPECT_EQ(retResult.GetX(), mmiPoint.GetX());
    EXPECT_EQ(retResult.GetY(), mmiPoint.GetY());
    EXPECT_EQ(retResult.GetZ(), mmiPoint.GetZ());
}

HWTEST_F(MouseEventTest, GetCursor_TMP_004, TestSize.Level1)
{
    MmiPoint mmiPoint(36, 26, 54);
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(31, 31, 31, 31, mmiPoint, 31, 31, 31, 31, 31, "313131",
                             31, 31, "313131", 31, false, deviceUdevTags, eventJoyStickInfo);
    MmiPoint retResult = mouseEventTmp.GetCursor();
    EXPECT_EQ(retResult.GetX(), mmiPoint.GetX());
    EXPECT_EQ(retResult.GetY(), mmiPoint.GetY());
    EXPECT_EQ(retResult.GetZ(), mmiPoint.GetZ());
}

HWTEST_F(MouseEventTest, GetXOffset_TMP_001, TestSize.Level1)
{
    float offsetX = 143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(25, 25, 25, 25, {25, 25, 25}, offsetX, 25, 25, 25, 25,
                             "252525", 25, 25, "252525", 25, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetXOffset();
    EXPECT_EQ(retResult, offsetX);
}
HWTEST_F(MouseEventTest, GetXOffset_TMP_002, TestSize.Level1)
{
    auto offsetX = static_cast<float>('i');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(22, 22, 22, 22, {22, 22, 22}, offsetX, 22, 22, 22, 22,
                             "222222", 22, 22, "222222", 22, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetXOffset();
    EXPECT_EQ(retResult, offsetX);
}

HWTEST_F(MouseEventTest, GetXOffset_TMP_003, TestSize.Level1)
{
    auto offsetX = static_cast<float>('i' + 'k');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(14, 14, 14, 14, {14, 14, 14}, offsetX, 14, 14, 14, 14,
                             "141414", 14, 14, "141414", 14, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetXOffset();
    EXPECT_EQ(retResult, offsetX);
}

HWTEST_F(MouseEventTest, GetXOffset_TMP_004, TestSize.Level1)
{
    float offsetX = -143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(31, 31, 31, 31, {31, 31, 31}, offsetX, 31, 31, 31, 31,
                             "313131", 31, 31, "313131", 31, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetXOffset();
    EXPECT_EQ(retResult, offsetX);
}

HWTEST_F(MouseEventTest, GetYOffset_TMP_001, TestSize.Level1)
{
    float offsetY = 143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(25, 25, 25, 25, {25, 25, 25}, 25, offsetY, 25, 25, 25,
                             "252525", 25, 25, "252525", 25, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetYOffset();
    EXPECT_EQ(retResult, offsetY);
}

HWTEST_F(MouseEventTest, GetYOffset_TMP_002, TestSize.Level1)
{
    auto offsetY = static_cast<float>('i');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(22, 22, 22, 22, {22, 22, 22}, 22, offsetY, 22, 22, 22,
                             "222222", 22, 22, "222222", 22, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetYOffset();
    EXPECT_EQ(retResult, offsetY);
}

HWTEST_F(MouseEventTest, GetYOffset_TMP_003, TestSize.Level1)
{
    auto offsetY = static_cast<float>('i' + 'k');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(14, 14, 14, 14, {14, 14, 14}, 14, offsetY, 14, 14, 14,
                             "141414", 14, 14, "141414", 14, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetYOffset();
    EXPECT_EQ(retResult, offsetY);
}

HWTEST_F(MouseEventTest, GetYOffset_TMP_004, TestSize.Level1)
{
    float offsetY = -143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(31, 31, 31, 31, {31, 31, 31}, 31, offsetY, 31, 31, 31,
                             "313131", 31, 31, "313131", 31, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetYOffset();
    EXPECT_EQ(retResult, offsetY);
}

HWTEST_F(MouseEventTest, GetCursorDelta_TMP_001, TestSize.Level1)
{
    float cursorDelta = 143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(25, 25, 25, 25, {25, 25, 25}, 25, 25, cursorDelta, 25, 25,
                             "252525", 25, 25, "252525", 25, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetCursorDelta(3301);
    EXPECT_EQ(retResult, cursorDelta);
}

HWTEST_F(MouseEventTest, GetCursorDelta_TMP_002, TestSize.Level1)
{
    auto cursorDelta = static_cast<float>('i');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(22, 22, 22, 22, {22, 22, 22}, 22, 22, cursorDelta, 22, 22,
                             "222222", 22, 22, "222222", 22, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetCursorDelta(3302);
    EXPECT_EQ(retResult, cursorDelta);
}

HWTEST_F(MouseEventTest, GetCursorDelta_TMP_003, TestSize.Level1)
{
    auto cursorDelta = static_cast<float>('i' + 'k');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(14, 14, 14, 14, {14, 14, 14}, 14, 14, cursorDelta, 14, 14,
                             "141414", 14, 14, "141414", 14, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetCursorDelta(3303);
    EXPECT_EQ(retResult, cursorDelta);
}

HWTEST_F(MouseEventTest, GetCursorDelta_TMP_004, TestSize.Level1)
{
    float cursorDelta = -143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(31, 31, 31, 31, {31, 31, 31}, 31, 31, cursorDelta, 31, 31,
                             "313131", 31, 31, "313131", 31, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetCursorDelta(3304);
    EXPECT_EQ(retResult, cursorDelta);
}

HWTEST_F(MouseEventTest, GetScrollingDelta_TMP_001, TestSize.Level1)
{
    float scrollingDelta = 143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(25, 25, 25, 25, {25, 25, 25}, 25, 25, 25, scrollingDelta, 25,
                             "252525", 25, 25, "252525", 25, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetScrollingDelta(5001);
    EXPECT_EQ(retResult, scrollingDelta);
}

HWTEST_F(MouseEventTest, GetScrollingDelta_TMP_002, TestSize.Level1)
{
    auto scrollingDelta = static_cast<float>('i');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(22, 22, 22, 22, {22, 22, 22}, 22, 22, 22, scrollingDelta, 22,
                             "222222", 22, 22, "222222", 22, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetScrollingDelta(5002);
    EXPECT_EQ(retResult, scrollingDelta);
}

HWTEST_F(MouseEventTest, GetScrollingDelta_TMP_003, TestSize.Level1)
{
    auto scrollingDelta = static_cast<float>('s' + 'k');
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(14, 14, 14, 14, {14, 14, 14}, 14, 14, 14, scrollingDelta, 14,
                             "141414", 14, 14, "141414", 14, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetScrollingDelta(5003);
    EXPECT_EQ(retResult, scrollingDelta);
}

HWTEST_F(MouseEventTest, GetScrollingDelta_TMP_004, TestSize.Level1)
{
    float scrollingDelta = -143135;
    MouseEvent mouseEventTmp;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTmp.Initialize(31, 31, 31, 31, {31, 31, 31}, 31, 31, 31, scrollingDelta, 31,
                             "313131", 31, 31, "313131", 31, false, deviceUdevTags, eventJoyStickInfo);
    float retResult = mouseEventTmp.GetScrollingDelta(5004);
    EXPECT_EQ(retResult, scrollingDelta);
}
} // namespace
