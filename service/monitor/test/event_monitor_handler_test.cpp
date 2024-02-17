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
#include <fstream>

#include "event_monitor_handler.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class EventMonitorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: EventMonitorHandlerTest_OnHandleEvent_001
 * @tc.desc: Test OnHandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventMonitorHandlerTest, EventMonitorHandlerTest_OnHandleEvent_001, TestSize.Level1)
{
    EventMonitorHandler eventMonitorHandler;
    auto keyEvent = KeyEvent::Create();
    eventMonitorHandler.HandleKeyEvent(keyEvent);
    ASSERT_EQ(eventMonitorHandler.OnHandleEvent(keyEvent), false);
    auto pointerEvent = PointerEvent::Create();
    eventMonitorHandler.HandlePointerEvent(pointerEvent);
    ASSERT_EQ(eventMonitorHandler.OnHandleEvent(pointerEvent), false);

    eventMonitorHandler.HandleTouchEvent(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetDeviceId(1);
    item.SetPointerId(0);
    item.SetDisplayX(523);
    item.SetDisplayY(723);
    item.SetPressure(5);
    pointerEvent->AddPointerItem(item);
    item.SetDisplayY(610);
    item.SetPointerId(1);
    item.SetDeviceId(1);
    item.SetPressure(7);
    item.SetDisplayX(600);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    keyEvent->SetActionTime(100);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->ActionToString(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->KeyCodeToString(KeyEvent::KEYCODE_BACK);
    KeyEvent::KeyItem part;
    part.SetKeyCode(KeyEvent::KEYCODE_BACK);
    part.SetDownTime(100);
    part.SetPressed(true);
    part.SetUnicode(0);
    keyEvent->AddKeyItem(part);

    eventMonitorHandler.HandlePointerEvent(pointerEvent);
    eventMonitorHandler.HandleTouchEvent(pointerEvent);
    ASSERT_EQ(eventMonitorHandler.OnHandleEvent(keyEvent), false);
    ASSERT_EQ(eventMonitorHandler.OnHandleEvent(pointerEvent), false);
}
} // namespace MMI
} // namespace OHOS
