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

#include "telephone_event_handler.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class TelephoneEventHandlerApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(TelephoneEventHandlerApiTest, Api_Test_OnAnswer, TestSize.Level1)
{
    TelephoneEventHandler telephoneEventHandlerTest;
    const MultimodalEvent event;
    auto retOnAnswer = telephoneEventHandlerTest.OnAnswer(event);
    EXPECT_EQ(retOnAnswer, false);
}

HWTEST_F(TelephoneEventHandlerApiTest, Api_Test_OnRefuse, TestSize.Level1)
{
    TelephoneEventHandler telephoneEventHandlerTest;
    const MultimodalEvent event;
    auto retOnRefuse = telephoneEventHandlerTest.OnRefuse(event);
    EXPECT_EQ(retOnRefuse, false);
}

HWTEST_F(TelephoneEventHandlerApiTest, Api_Test_OOnHangup, TestSize.Level1)
{
    TelephoneEventHandler telephoneEventHandlerTest;
    const MultimodalEvent event;
    auto retOnHangup = telephoneEventHandlerTest.OnHangup(event);
    EXPECT_EQ(retOnHangup, false);
}

HWTEST_F(TelephoneEventHandlerApiTest, Api_Test_OnTelephoneControl, TestSize.Level1)
{
    TelephoneEventHandler telephoneEventHandlerTest;
    const MultimodalEvent event;
    auto retOnTelephoneControl = telephoneEventHandlerTest.OnTelephoneControl(event);
    EXPECT_EQ(retOnTelephoneControl, false);
}
} // namespace
