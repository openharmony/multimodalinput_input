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
#include "mmi_server.h"
#include "mmi_interface.h"
#include "event_dump.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

class DfxDumpTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
protected:
    const uint16_t WAITING_ENENTS_TIME = 15;
};

#ifdef DUMP

HWTEST_F(DfxDumpTest, Test_Dump, TestSize.Level1)
{
    Start();
    std::this_thread::sleep_for(std::chrono::seconds(WAITING_ENENTS_TIME));
    MMIEventDump->TestDump();
}
#endif
} // namespace
