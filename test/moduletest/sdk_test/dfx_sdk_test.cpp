/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "mmi_server.h"
#include "client_msg_handler.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class DfxSdkTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class DfxClientTest : public ClientMsgHandler {
public:
    int32_t GetMultimodeInputInfoClientTest(const UDSClient& client, NetPacket& pkt)
    {
        return GetMultimodeInputInfo(client, pkt);
    }
};

#ifdef SDK

HWTEST_F(DfxSdkTest, Test_Client_SDK, TestSize.Level1)
{
    Start();
    DfxTest sdkTest;
    UDSClient client;
    NetPacket newPacket(static_cast<MmiMessageId>(1));
    sdkTest.Init();
    auto ret = clientSdkTest.GetMultimodeInputInfoClientTest(client, newPacket);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    EXPECT_EQ(ret, RET_OK);
}
#endif
} // namespace
