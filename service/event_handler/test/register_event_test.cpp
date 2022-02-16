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
#include "register_event.h"
#include "input-event-codes.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class RegisterEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class RegisterEventUnitTest : public RegisterEvent {
public:
    void SetTimeCount(uint64_t timeCount)
    {
        timeCount_ = timeCount;
    }

    bool OnGetRepeatKetStateUnitTest(const int32_t keyCode, MmiMessageId& msgId)
    {
        return OnGetRepeatKetState(keyCode, msgId);
    }

    int32_t OnEventKeyJudgeUnitTest(const int32_t keyCode, MmiMessageId& msgId)
    {
        EventKeyboard key = {};
        key.key = keyCode;
        return OnEventKeyJudge(key, msgId, key);
    }

    int32_t BitSetOneUnitTest(const int32_t signCode, const int16_t bitCode) const
    {
        return BitSetOne(signCode, bitCode);
    }
};

HWTEST_F(RegisterEventTest, OnEventPointAxis_001, TestSize.Level1)
{
    RegisterEvent registerEvent;
    MmiMessageId msg = MmiMessageId::INVALID;
    EventPointer point = {};
    point.axis = POINTER_AXIS_SCROLL_VERTICAL;
    point.source = POINTER_AXIS_SOURCE_WHEEL;
    point.delta.y = 15;
    auto retResult = registerEvent.OnEventPointAxis(point, msg);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(RegisterEventTest, OnEventPointAxis_002, TestSize.Level1)
{
    RegisterEvent registerEvent;
    MmiMessageId msg = MmiMessageId::INVALID;
    EventPointer point = {};
    point.axis = POINTER_AXIS_SCROLL_VERTICAL;
    point.source = POINTER_AXIS_SOURCE_WHEEL;
    point.delta.y = -15;
    auto retResult = registerEvent.OnEventPointAxis(point, msg);
    EXPECT_EQ(retResult, RET_OK);
}

HWTEST_F(RegisterEventTest, OnEventKeyGetSign_001, TestSize.Level1)
{
    RegisterEvent registerEvent;
    MmiMessageId msg = MmiMessageId::INVALID;
    EventKeyboard key = {};
    EventKeyboard prevKey = {};
    key.key = 1;
    key.state = KEY_STATE_RELEASED;
    registerEvent.OnEventKeyGetSign(key, msg, prevKey);
}

HWTEST_F(RegisterEventTest, OnGetRepeatKetState_001, TestSize.Level1)
{
    MmiMessageId msg = MmiMessageId::INVALID;
    RegisterEventUnitTest registerEventUnit;

    registerEventUnit.OnGetRepeatKetStateUnitTest(1, msg);
}

HWTEST_F(RegisterEventTest, OnEventKeyJudge_001, TestSize.Level1)
{
    MmiMessageId msg = MmiMessageId::INVALID;
    RegisterEventUnitTest registerEventUnit;

    registerEventUnit.OnEventKeyJudgeUnitTest(1, msg);
}

HWTEST_F(RegisterEventTest, BitSetOne_001, TestSize.Level1)
{
    RegisterEventUnitTest registerEventUnit;
    auto retResult = registerEventUnit.BitSetOneUnitTest(1, 1);
    EXPECT_NE(retResult, 1);
}

HWTEST_F(RegisterEventTest, OnEventPointButton_001, TestSize.Level1)
{
    RegisterEvent registerEvent;
    MmiMessageId msg = MmiMessageId::INVALID;
    RegisterEventUnitTest registerEventUnit;

    registerEventUnit.SetTimeCount(0);
    registerEvent.OnEventPointButton(BTN_MIDDLE, 1, BUTTON_STATE_PRESSED, msg);
}

HWTEST_F(RegisterEventTest, OnEventPointButton_002, TestSize.Level1)
{
    RegisterEvent registerEvent;
    MmiMessageId msg = MmiMessageId::INVALID;
    RegisterEventUnitTest registerEventUnit;

    registerEventUnit.SetTimeCount(10);
    registerEvent.OnEventPointButton(BTN_RIGHT, 11, BUTTON_STATE_PRESSED, msg);
}

HWTEST_F(RegisterEventTest, OnEventPointButton_003, TestSize.Level1)
{
    RegisterEvent registerEvent;
    MmiMessageId msg = MmiMessageId::INVALID;
    RegisterEventUnitTest registerEventUnit;

    registerEventUnit.SetTimeCount(10);
    registerEvent.OnEventPointButton(BTN_MIDDLE, 11, BUTTON_STATE_RELEASED, msg);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_01, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = 0;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_02, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = 0;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_03, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = 0;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_04, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = 0;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_05, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = 0;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_06, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = 0;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_07, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = 100000;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_08, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = 100000;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_09, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = -100000;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_010, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = -100000;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_011, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = -1;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchInfo_012, TestSize.Level1)
{
    RegisterEvent registerEvent;
    EventTouch touch = {};
    int32_t seatSlot = -1;
    uint32_t deviceId = 1;
    registerEvent.GetTouchInfo(std::make_pair(deviceId, seatSlot), touch);
}

HWTEST_F(RegisterEventTest, GetTouchIds_01, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::vector<std::pair<uint32_t, int32_t>> touchIds;
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_02, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, 0);
    std::pair<uint32_t, int32_t> element2(1, 0);
    std::pair<uint32_t, int32_t> element3(1, 0);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = {element1, element2, element3};
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_03, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, -1);
    std::pair<uint32_t, int32_t> element2(1, -1);
    std::pair<uint32_t, int32_t> element3(1, -1);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = { element1, element2, element3 };
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_04, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, -1);
    std::pair<uint32_t, int32_t> element2(1, 0);
    std::pair<uint32_t, int32_t> element3(1, -1);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = {element1, element2, element3};
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_05, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, -1);
    std::pair<uint32_t, int32_t> element2(1, 0);
    std::pair<uint32_t, int32_t> element3(1, 0);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = { element1, element2, element3 };
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_06, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, 0);
    std::pair<uint32_t, int32_t> element2(1, -1);
    std::pair<uint32_t, int32_t> element3(1, 0);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = { element1, element2, element3 };
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_07, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, 0);
    std::pair<uint32_t, int32_t> element2(1, 0);
    std::pair<uint32_t, int32_t> element3(1, -1);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = { element1, element2, element3 };
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_08, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, 0);
    std::pair<uint32_t, int32_t> element2(1, 0);
    std::pair<uint32_t, int32_t> element3(1, -100000);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = { element1, element2, element3 };
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_09, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, 0);
    std::pair<uint32_t, int32_t> element2(1, 0);
    std::pair<uint32_t, int32_t> element3(1, 100000);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = { element1, element2, element3 };
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_010, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, -100000);
    std::pair<uint32_t, int32_t> element2(1, -100000);
    std::pair<uint32_t, int32_t> element3(1, -100000);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = { element1, element2, element3 };
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_011, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, 100000);
    std::pair<uint32_t, int32_t> element2(1, 100000);
    std::pair<uint32_t, int32_t> element3(1, 100000);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = { element1, element2, element3 };
    registerEvent.GetTouchIds(1, touchIds);
}

HWTEST_F(RegisterEventTest, GetTouchIds_012, TestSize.Level1)
{
    RegisterEvent registerEvent;
    std::pair<uint32_t, int32_t> element1(1, 0);
    std::pair<uint32_t, int32_t> element2(1, 0);
    std::pair<uint32_t, int32_t> element3(1, 0);
    std::pair<uint32_t, int32_t> element4(1, 0);
    std::vector<std::pair<uint32_t, int32_t>> touchIds = { element1, element2, element3, element4 };
    registerEvent.GetTouchIds(1, touchIds);
}
} // namespace
