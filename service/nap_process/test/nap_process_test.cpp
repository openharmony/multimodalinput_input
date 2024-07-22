/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <fstream>

#include <gtest/gtest.h>

#include "nap_process.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t REMOVE_OBSERVER = -2;
constexpr int32_t NAP_EVENT = 0;
constexpr int32_t SUBSCRIBED = 1;
constexpr int32_t ACTIVE_EVENT = 2;
} // namespace

class NapProcessTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: NapProcessTest_Init_001
 * @tc.desc: Test init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_Init_001, TestSize.Level1)
{
    UDSServer udsServer;
    NapProcess napProcess;
    napProcess.Init(udsServer);
    ASSERT_EQ(&udsServer, napProcess.udsServer_);
}

/**
 * @tc.name: NapProcessTest_NotifyBundleName_001
 * @tc.desc: Test notify bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_NotifyBundleName_001, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data;
    data.pid = -1;
    data.uid = 1000;
    data.bundleName = "com.example.app";
    int32_t syncState = 1;
    int32_t result = napProcess.NotifyBundleName(data, syncState);
    ASSERT_EQ(result, RET_ERR);
    data.pid = 1234;
    result = napProcess.NotifyBundleName(data, syncState);
    ASSERT_EQ(result, RET_ERR);
}

/**
 * @tc.name: NapProcessTest_IsNeedNotify_001
 * @tc.desc: Test is need notify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_IsNeedNotify_001, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data;
    data.pid = 1;
    data.uid = 1;
    data.bundleName = "bundleName";
    napProcess.napMap_[data] = SUBSCRIBED;
    ASSERT_TRUE(napProcess.IsNeedNotify(data));
    napProcess.napMap_[data] = NAP_EVENT;
    ASSERT_TRUE(napProcess.IsNeedNotify(data));
    napProcess.napMap_[data] = REMOVE_OBSERVER;
    ASSERT_FALSE(napProcess.IsNeedNotify(data));
    napProcess.napMap_[data] = ACTIVE_EVENT;
    ASSERT_FALSE(napProcess.IsNeedNotify(data));
}

/**
 * @tc.name: NapProcessTest_SetNapStatus_001
 * @tc.desc: Test set nap status
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_SetNapStatus_001, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t pid = 1234;
    int32_t uid = 4321;
    std ::string bundleName = "testBundle";
    int32_t napStatus = ACTIVE_EVENT;
    ASSERT_EQ(napProcess.SetNapStatus(pid, uid, bundleName, napStatus), RET_OK);
    napStatus = NAP_EVENT;
    ASSERT_EQ(napProcess.SetNapStatus(pid, uid, bundleName, napStatus), RET_OK);
    napStatus = 3;
    ASSERT_EQ(napProcess.SetNapStatus(pid, uid, bundleName, napStatus), RET_OK);
}

/**
 * @tc.name: NapProcessTest_AddMmiSubscribedEventData_001
 * @tc.desc:Add mmi subscribed event data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_AddMmiSubscribedEventData_001, TestSize.Level1)
{
    NapProcess process;
    NapProcess::NapStatusData data;
    int32_t syncState = 2;
    int32_t result = process.AddMmiSubscribedEventData(data, syncState);
    ASSERT_EQ(result, RET_OK);
    ASSERT_EQ(process.napMap_[data], syncState);
    int32_t newsyncState = 2;
    process.AddMmiSubscribedEventData(data, syncState);
    result = process.AddMmiSubscribedEventData(data, newsyncState);
    ASSERT_EQ(result, RET_OK);
    ASSERT_EQ(process.napMap_[data], syncState);
}

/**
 * @tc.name: NapProcessTest_RemoveMmiSubscribedEventData_001
 * @tc.desc: Test remove mmi subscribed event data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_RemoveMmiSubscribedEventData_001, TestSize.Level1)
{
    NapProcess process;
    NapProcess::NapStatusData napData;
    int32_t syncState = 1;
    int32_t ret = process.RemoveMmiSubscribedEventData(napData);
    ASSERT_EQ(ret, RET_OK);
    process.AddMmiSubscribedEventData(napData, syncState);
    ret = process.RemoveMmiSubscribedEventData(napData);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: NapProcessTest_GetNapClientPid_001
 * @tc.desc: Test get nap client pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_GetNapClientPid_001, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t expectedPid = 1234;
    napProcess.napClientPid_ = expectedPid;
    int32_t actualPid = napProcess.GetNapClientPid();
    ASSERT_EQ(expectedPid, actualPid);
}

/**
 * @tc.name: NapProcessTest_NotifyNapOnline_001
 * @tc.desc: Test notify nap online
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_NotifyNapOnline_001, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t result = napProcess.NotifyNapOnline();
    ASSERT_NE(napProcess.GetNapClientPid(), result);
}

/**
 * @tc.name: NapProcessTest_RemoveInputEventObserver_001
 * @tc.desc: Test remove input event observer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_RemoveInputEventObserver_001, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t ret = napProcess.RemoveInputEventObserver();
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(napProcess.napMap_.empty());
    ASSERT_EQ(napProcess.napClientPid_, REMOVE_OBSERVER);
}

/**
 * @tc.name: NapProcessTest_GetAllMmiSubscribedEvents_001
 * @tc.desc: Test get all mmi subscribed events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_GetAllMmiSubscribedEvents_001, TestSize.Level1)
{
    NapProcess napProcess;
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> datas;
    ASSERT_EQ(napProcess.GetAllMmiSubscribedEvents(datas), RET_OK);
    ASSERT_TRUE(datas.empty());
}
} // namespace MMI
} // namespace OHOS