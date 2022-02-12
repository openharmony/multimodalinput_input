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

#include "standard_event_handler.h"
#include <gtest/gtest.h>
#include "libinput-private.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class StandardEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(StandardEventHandlerTest, TEST_StandardTouchEvent_PointerButton, TestSize.Level1)
{
    libinput_event event;
    StandardTouchStruct data;
    event.device = (libinput_device*)zalloc(sizeof(libinput_device*));
    event.device->seat = (libinput_seat*)zalloc(sizeof(libinput_seat*));
    event.device->seat->libinput = (libinput*)zalloc(sizeof(libinput*));
    StandardEventHandler mmiStandard;

    event.type = LIBINPUT_EVENT_POINTER_BUTTON;
    mmiStandard.StandardTouchEvent(&event, data);
    EXPECT_EQ(data.curRventType, RET_ERR);
    free(event.device->seat->libinput);
    free(event.device->seat);
    free(event.device);
}

HWTEST_F(StandardEventHandlerTest, TEST_StandardTouchEvent_PointerMotion, TestSize.Level1)
{
    libinput_event event;
    StandardTouchStruct data;
    event.device = (libinput_device*)zalloc(sizeof(libinput_device*));
    event.device->seat = (libinput_seat*)zalloc(sizeof(libinput_seat*));
    event.device->seat->libinput = (libinput*)zalloc(sizeof(libinput*));
    StandardEventHandler mmiStandard;

    event.type = LIBINPUT_EVENT_POINTER_MOTION;
    mmiStandard.StandardTouchEvent(&event, data);
    EXPECT_EQ(data.curRventType, RET_ERR);
    free(event.device->seat->libinput);
    free(event.device->seat);
    free(event.device);
}

HWTEST_F(StandardEventHandlerTest, TEST_StandardTouchEvent_TableToolTip, TestSize.Level1)
{
    libinput_event event;
    StandardTouchStruct data;
    event.device = (libinput_device*)zalloc(sizeof(libinput_device*));
    event.device->seat = (libinput_seat*)zalloc(sizeof(libinput_seat*));
    event.device->seat->libinput = (libinput*)zalloc(sizeof(libinput*));
    StandardEventHandler mmiStandard;

    event.type = LIBINPUT_EVENT_TABLET_TOOL_TIP;
    mmiStandard.StandardTouchEvent(&event, data);
    EXPECT_EQ(data.curRventType, RET_ERR);
    free(event.device->seat->libinput);
    free(event.device->seat);
    free(event.device);
}

HWTEST_F(StandardEventHandlerTest, TEST_StandardTouchEvent_Other, TestSize.Level1)
{
    libinput_event event;
    StandardTouchStruct data;
    event.device = (libinput_device*)zalloc(sizeof(libinput_device*));
    event.device->seat = (libinput_seat*)zalloc(sizeof(libinput_seat*));
    event.device->seat->libinput = (libinput*)zalloc(sizeof(libinput*));
    StandardEventHandler mmiStandard;

    event.type = LIBINPUT_EVENT_NONE;
    mmiStandard.StandardTouchEvent(&event, data);
    EXPECT_EQ(data.curRventType, RET_ERR);
    free(event.device->seat->libinput);
    free(event.device->seat);
    free(event.device);
}
} // namespace
