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

#include "message_send_recv_stat_mgr.h"
#include <gtest/gtest.h>
#include "proto.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace std;
class MessageSendRecvStatMgrTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    MessageSendRecvStatMgr messageSendRecvStatMgr;
};

HWTEST_F(MessageSendRecvStatMgrTest, Test_Increase, TestSize.Level1)
{
    messageSendRecvStatMgr.Increase();
}

HWTEST_F(MessageSendRecvStatMgrTest, Test_Decrease, TestSize.Level1)
{
    messageSendRecvStatMgr.Decrease();
}

HWTEST_F(MessageSendRecvStatMgrTest, Test_IsNoWaitMessage, TestSize.Level1)
{
    messageSendRecvStatMgr.IsNoWaitMessage();
}
} // namespace