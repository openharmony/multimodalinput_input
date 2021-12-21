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
#include "client_msg_handler.h"
#include "event_factory.h"

namespace {
using namespace testing::ext;
using namespace OHOS;

class EventFactoryTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: CreateEvent_multimodal
 * @tc.desc: detection create event:  EVENT_MULTIMODAL
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_multimodal, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_MULTIMODAL);
}

/**
 * @tc.name: CreateEvent_key
 * @tc.desc: detection create event:  EVENT_KEY
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_key, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_KEY);
}

/**
 * @tc.name: CreateEvent_keyBoard
 * @tc.desc: detection create event:  EVENT_KEYBOARD
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_keyBoard, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_KEYBOARD);
}

/**
 * @tc.name: CreateEvent_rocker
 * @tc.desc: detection create event:  EVENT_ROCKER
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_rocker, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_ROCKER);
}

/**
 * @tc.name: CreateEvent_remoteControl
 * @tc.desc: detection create event:  EVENT_REMOTECONTROL
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_remoteControl, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_REMOTECONTROL);
}

/**
 * @tc.name: CreateEvent_joyStick
 * @tc.desc: detection create event:  EVENT_JOYSTICK
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_joyStick, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_JOYSTICK);
}

/**
 * @tc.name: CreateEvent_mouse
 * @tc.desc: detection create event:  EVENT_MOUSE
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_mouse, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_MOUSE);
}

/**
 * @tc.name: CreateEvent_trackBoll
 * @tc.desc: detection create event:  EVENT_TRACKBOLL
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_trackBoll, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_TRACKBOLL);
}

/**
 * @tc.name: CreateEvent_manipulation
 * @tc.desc: detection create event:  EVENT_MANIPULATION
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_manipulation, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_MANIPULATION);
}

/**
 * @tc.name: CreateEvent_touch
 * @tc.desc: detection create event:  EVENT_TOUCH
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_touch, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_TOUCH);
}

/**
 * @tc.name: CreateEvent_touchPad
 * @tc.desc: detection create event:  EVENT_TOUCHPAD
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_touchPad, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_TOUCHPAD);
}

/**
 * @tc.name: CreateEvent_stylus
 * @tc.desc: detection create event:  EVENT_STYLUS
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_stylus, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_STYLUS);
}

/**
 * @tc.name: CreateEvent_rotation
 * @tc.desc: detection create event:  EVENT_ROTATION
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_rotation, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_ROTATION);
}

/**
 * @tc.name: CreateEvent_speech
 * @tc.desc: detection create event:  EVENT_SPEECH
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_speech, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_SPEECH);
}

/**
 * @tc.name: CreateEvent_builtInKey
 * @tc.desc: detection create event:  EVENT_BUILTINKEY
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_builtInKey, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_BUILTINKEY);
}

/**
 * @tc.name: CreateEvent_composite
 * @tc.desc: detection create event:  EVENT_COMPOSITE
 * @tc.type: FUNC
 * @tc.require: AR00000000 SR00000000
 */
HWTEST_F(EventFactoryTest, CreateEvent_composite, TestSize.Level1)
{
    EventFactory::CreateEvent(EVENT_COMPOSITE);
}
} // namespace
