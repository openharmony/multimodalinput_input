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
#include "test_aux_tool_client.h"

namespace {
using namespace testing::ext;
using namespace std;
using namespace OHOS::MMI;

class LibmmiAisensorClientTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MMIAisensorClientTests : public TestAuxToolClient {
public:
    void OnDisconnectedTest()
    {
        OnDisconnected();
    }
    void OnConnectedTest()
    {
        OnConnected();
    }
};

HWTEST_F(LibmmiAisensorClientTest, OnConnected_Test_001, TestSize.Level1)
{
    MMIAisensorClientTests aiSensor;
    aiSensor.OnConnectedTest();
}

HWTEST_F(LibmmiAisensorClientTest, OnDisconnected_Test_001, TestSize.Level1)
{
    MMIAisensorClientTests aiSensor;
    aiSensor.OnDisconnectedTest();
}
} // namespace
