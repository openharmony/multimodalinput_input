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
using namespace OHOS;

class MouseEventApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(MouseEventApiTest, Api_Test_GetAction_Normal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 0;
    int32_t pressedButtons = 0;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
                              scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
                              isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retAction = mouseEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetAction_Abnormal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 0xFFFFFFFF;
    int32_t actionButton = 0;
    int32_t pressedButtons = 0;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retAction = mouseEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetAction_Min, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = static_cast<int32_t>(0xFFFFFFFF);
    int32_t actionButton = 0;
    int32_t pressedButtons = 0;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retAction = mouseEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetAction_Max, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 0x7FFFFFFF;
    int32_t actionButton = 0;
    int32_t pressedButtons = 0;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retAction = mouseEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetActionButton_Normal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 0;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retActionButton = mouseEventTest.GetActionButton();
    EXPECT_EQ(retActionButton, actionButton);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetActionButton_Abnormal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 0xFFFFFFFF;
    int32_t pressedButtons = 0;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retActionButton = mouseEventTest.GetActionButton();
    EXPECT_EQ(retActionButton, actionButton);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetActionButton_Min, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = static_cast<int32_t>(0xFFFFFFFF);
    int32_t pressedButtons = 0;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retActionButton = mouseEventTest.GetActionButton();
    EXPECT_EQ(retActionButton, actionButton);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetActionButton_Max, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 0x7FFFFFFF;
    int32_t pressedButtons = 0;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retActionButton = mouseEventTest.GetActionButton();
    EXPECT_EQ(retActionButton, actionButton);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetPressedButtons_Normal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 5;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retPressedButtons = mouseEventTest.GetPressedButtons();
    EXPECT_EQ(retPressedButtons, pressedButtons);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetPressedButtons_Abnormal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 0xFFFFFFFF;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retPressedButtons = mouseEventTest.GetPressedButtons();
    EXPECT_EQ(retPressedButtons, pressedButtons);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetPressedButtons_Min, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = static_cast<int32_t>(0xFFFFFFFF);
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retPressedButtons = mouseEventTest.GetPressedButtons();
    EXPECT_EQ(retPressedButtons, pressedButtons);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetPressedButtons_Max, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 0x7FFFFFFF;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retPressedButtons = mouseEventTest.GetPressedButtons();
    EXPECT_EQ(retPressedButtons, pressedButtons);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetCursor_Normal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 5;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retCursor = mouseEventTest.GetCursor();
    float px = 0.56f;
    float py = 15.548f;
    retCursor.Setxy(px, py);
    auto retX = retCursor.GetX();
    EXPECT_FLOAT_EQ(retX, px);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetCursor_Abnormal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 5;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    auto retCursor = mouseEventTest.GetCursor();
    auto px = static_cast<float>(0xFFFFFFFFFFFFFFFF);
    float py = 15.548f;
    retCursor.Setxy(px, py);
    auto retX = retCursor.GetX();
    EXPECT_FLOAT_EQ(retX, px);
}

HWTEST_F(MouseEventApiTest, Api_Test_SetCursorOffset_GetXOffset_Normal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    float offsetX = 48.185f;
    float offsetY = 3.545f;
    mouseEventTest.SetCursorOffset(offsetX, offsetY);
    auto retXOffset = mouseEventTest.GetXOffset();
    EXPECT_FLOAT_EQ(retXOffset, offsetX);
}

HWTEST_F(MouseEventApiTest, Api_Test_SetCursorOffset_GetXOffset_Abnormal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    float offsetX = static_cast<float>(0xFFFFFFFFFFFFFFFF);
    float offsetY = 3.545f;
    mouseEventTest.SetCursorOffset(offsetX, offsetY);
    auto retXOffset = mouseEventTest.GetXOffset();
    EXPECT_FLOAT_EQ(retXOffset, offsetX);
}

HWTEST_F(MouseEventApiTest, Api_Test_SetCursorOffset_GetYOffset_Normal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    float offsetX = 48.185f;
    float offsetY = 3.545f;
    mouseEventTest.SetCursorOffset(offsetX, offsetY);
    auto retYOffset = mouseEventTest.GetYOffset();
    EXPECT_FLOAT_EQ(retYOffset, offsetY);
}

HWTEST_F(MouseEventApiTest, Api_Test_SetCursorOffset_GetYOffset_Abnormal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    float offsetX = 48.185f;
    auto offsetY = static_cast<float>(0xFFFFFFFFFFFFFFFF);
    mouseEventTest.SetCursorOffset(offsetX, offsetY);
    auto retYOffset = mouseEventTest.GetYOffset();
    EXPECT_FLOAT_EQ(retYOffset, offsetY);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetAxisValue_Normal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 5;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo;
    eventJoyStickInfo.abs_rx.standardValue = 0.15f;
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    int32_t axis = AXIS_RX;
    auto retAxisValue = mouseEventTest.GetAxisValue(axis);
    EXPECT_FLOAT_EQ(retAxisValue, eventJoyStickInfo.abs_rx.standardValue);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetAxisValue_Anomalous, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 5;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo;
    eventJoyStickInfo.abs_rx.standardValue = 0.15f;
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    int32_t axis = 100;
    auto retAxisValue = mouseEventTest.GetAxisValue(axis);
    EXPECT_FLOAT_EQ(retAxisValue, 0.0f);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetCursorDelta_Normal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 5;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 1.54f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    int32_t axis = -1;
    auto retCursorDelta = mouseEventTest.GetCursorDelta(axis);
    EXPECT_FLOAT_EQ(retCursorDelta, cursorDelta);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetCursorDelta_Abnormal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 5;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    auto cursorDelta = static_cast<float>(0xFFFFFFFFFFFFFFFF);
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    const EventJoyStickAxis eventJoyStickInfo = {};
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    int32_t axis = -1;
    auto retCursorDelta = mouseEventTest.GetCursorDelta(axis);
    EXPECT_FLOAT_EQ(retCursorDelta, cursorDelta);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetScrollingDelta_Normal, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 5;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo;
    eventJoyStickInfo.abs_rx.standardValue = 0.15f;
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    int32_t axis = AXIS_RX;
    auto retScrollingDelta = mouseEventTest.GetScrollingDelta(axis);
    EXPECT_FLOAT_EQ(retScrollingDelta, eventJoyStickInfo.abs_rx.standardValue);
}

HWTEST_F(MouseEventApiTest, Api_Test_GetScrollingDelta_Anomalous, TestSize.Level1)
{
    MouseEvent mouseEventTest;
    int32_t windowId = 0;
    int32_t action = 10;
    int32_t actionButton = 10;
    int32_t pressedButtons = 5;
    const MmiPoint mmiPoint = {};
    float xOffset = 0.0f;
    float yOffset = 0.0f;
    float cursorDelta = 0.0f;
    float scrollingDelta = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    EventJoyStickAxis eventJoyStickInfo;
    eventJoyStickInfo.abs_rx.standardValue = 0.15f;
    mouseEventTest.Initialize(windowId, action, actionButton, pressedButtons, mmiPoint, xOffset, yOffset, cursorDelta,
        scrollingDelta, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags, eventJoyStickInfo);
    int32_t axis = 100;
    auto retScrollingDelta = mouseEventTest.GetScrollingDelta(axis);
    EXPECT_FLOAT_EQ(retScrollingDelta, 0.0f);
}
} // namespace
