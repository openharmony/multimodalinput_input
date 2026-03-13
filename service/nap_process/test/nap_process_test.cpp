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

    napProcess.napClientPid_ = 0;
    result = napProcess.NotifyBundleName(data, syncState);
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

/**
 * @tc.name: NapProcessTest_GetAllMmiSubscribedEvents_002
 * @tc.desc: Test get all mmi subscribed events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_GetAllMmiSubscribedEvents_002, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data;
    data.pid = 1;
    data.uid = 1;
    data.bundleName = "bundleName";
    napProcess.napMap_[data] = SUBSCRIBED;
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> datas;
    ASSERT_EQ(napProcess.GetAllMmiSubscribedEvents(datas), RET_OK);
    ASSERT_FALSE(datas.empty());
}

/**
 * @tc.name: NapProcessTest_Init_002
 * @tc.desc: Test init with null server pointer boundary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_Init_002, TestSize.Level1)
{
    NapProcess napProcess;
    UDSServer udsServer;
    napProcess.Init(udsServer);
    ASSERT_NE(nullptr, napProcess.udsServer_);
}

/**
 * @tc.name: NapProcessTest_NotifyBundleName_002
 * @tc.desc: Test notify bundle name with empty bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_NotifyBundleName_002, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data;
    data.pid = 1234;
    data.uid = 1000;
    data.bundleName = "";
    int32_t syncState = 1;
    napProcess.napClientPid_ = 1234;
    int32_t result = napProcess.NotifyBundleName(data, syncState);
    ASSERT_EQ(result, RET_ERR);
}

/**
 * @tc.name: NapProcessTest_NotifyBundleName_003
 * @tc.desc: Test notify bundle name with negative uid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_NotifyBundleName_003, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data;
    data.pid = 1234;
    data.uid = -1;
    data.bundleName = "com.example.app";
    int32_t syncState = 0;
    napProcess.napClientPid_ = 1234;
    int32_t result = napProcess.NotifyBundleName(data, syncState);
    ASSERT_EQ(result, RET_ERR);
}

/**
 * @tc.name: NapProcessTest_NotifyBundleName_004
 * @tc.desc: Test notify bundle name with max syncState value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_NotifyBundleName_004, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data;
    data.pid = 1234;
    data.uid = 1000;
    data.bundleName = "com.example.app";
    int32_t syncState = INT32_MAX;
    napProcess.napClientPid_ = 1234;
    int32_t result = napProcess.NotifyBundleName(data, syncState);
    ASSERT_EQ(result, RET_ERR);
}

/**
 * @tc.name: NapProcessTest_IsNeedNotify_002
 * @tc.desc: Test is need notify with empty napMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_IsNeedNotify_002, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data;
    data.pid = 1;
    data.uid = 1;
    data.bundleName = "bundleName";
    ASSERT_FALSE(napProcess.IsNeedNotify(data));
}

/**
 * @tc.name: NapProcessTest_IsNeedNotify_003
 * @tc.desc: Test is need notify with different pid uid bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_IsNeedNotify_003, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data1;
    data1.pid = 1;
    data1.uid = 1;
    data1.bundleName = "bundleName1";
    napProcess.napMap_[data1] = SUBSCRIBED;
    
    NapProcess::NapStatusData data2;
    data2.pid = 2;
    data2.uid = 2;
    data2.bundleName = "bundleName2";
    ASSERT_FALSE(napProcess.IsNeedNotify(data2));
}

/**
 * @tc.name: NapProcessTest_SetNapStatus_002
 * @tc.desc: Test set nap status with negative pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_SetNapStatus_002, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t pid = -1;
    int32_t uid = 4321;
    std::string bundleName = "testBundle";
    int32_t napStatus = ACTIVE_EVENT;
    ASSERT_EQ(napProcess.SetNapStatus(pid, uid, bundleName, napStatus), RET_OK);
}

/**
 * @tc.name: NapProcessTest_SetNapStatus_003
 * @tc.desc: Test set nap status with empty bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_SetNapStatus_003, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t pid = 1234;
    int32_t uid = 4321;
    std::string bundleName = "";
    int32_t napStatus = NAP_EVENT;
    ASSERT_EQ(napProcess.SetNapStatus(pid, uid, bundleName, napStatus), RET_OK);
}

/**
 * @tc.name: NapProcessTest_SetNapStatus_004
 * @tc.desc: Test set nap status with invalid napStatus value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_SetNapStatus_004, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t pid = 1234;
    int32_t uid = 4321;
    std::string bundleName = "testBundle";
    int32_t napStatus = -1;
    ASSERT_EQ(napProcess.SetNapStatus(pid, uid, bundleName, napStatus), RET_OK);
    
    napStatus = INT32_MAX;
    ASSERT_EQ(napProcess.SetNapStatus(pid, uid, bundleName, napStatus), RET_OK);
}

/**
 * @tc.name: NapProcessTest_AddMmiSubscribedEventData_002
 * @tc.desc: Test add mmi subscribed event data with negative syncState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_AddMmiSubscribedEventData_002, TestSize.Level1)
{
    NapProcess process;
    NapProcess::NapStatusData data;
    data.pid = 1;
    data.uid = 1;
    data.bundleName = "testBundle";
    int32_t syncState = -1;
    int32_t result = process.AddMmiSubscribedEventData(data, syncState);
    ASSERT_EQ(result, RET_OK);
    ASSERT_EQ(process.napMap_[data], syncState);
}

/**
 * @tc.name: NapProcessTest_AddMmiSubscribedEventData_003
 * @tc.desc: Test add mmi subscribed event data multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_AddMmiSubscribedEventData_003, TestSize.Level1)
{
    NapProcess process;
    NapProcess::NapStatusData data;
    data.pid = 1;
    data.uid = 1;
    data.bundleName = "testBundle";
    
    for (int32_t i = 0; i < 5; i++) {
        int32_t result = process.AddMmiSubscribedEventData(data, i);
        ASSERT_EQ(result, RET_OK);
        ASSERT_EQ(process.napMap_[data], i);
    }
}

/**
 * @tc.name: NapProcessTest_RemoveMmiSubscribedEventData_002
 * @tc.desc: Test remove mmi subscribed event data not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_RemoveMmiSubscribedEventData_002, TestSize.Level1)
{
    NapProcess process;
    NapProcess::NapStatusData napData;
    napData.pid = 999;
    napData.uid = 999;
    napData.bundleName = "nonExistBundle";
    int32_t ret = process.RemoveMmiSubscribedEventData(napData);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: NapProcessTest_RemoveMmiSubscribedEventData_003
 * @tc.desc: Test remove mmi subscribed event data multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_RemoveMmiSubscribedEventData_003, TestSize.Level1)
{
    NapProcess process;
    NapProcess::NapStatusData napData;
    napData.pid = 1;
    napData.uid = 1;
    napData.bundleName = "testBundle";
    
    process.AddMmiSubscribedEventData(napData, 1);
    int32_t ret = process.RemoveMmiSubscribedEventData(napData);
    ASSERT_EQ(ret, RET_OK);
    
    ret = process.RemoveMmiSubscribedEventData(napData);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: NapProcessTest_GetNapClientPid_002
 * @tc.desc: Test get nap client pid with default value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_GetNapClientPid_002, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t actualPid = napProcess.GetNapClientPid();
    ASSERT_EQ(actualPid, -1);
}

/**
 * @tc.name: NapProcessTest_GetNapClientPid_003
 * @tc.desc: Test get nap client pid with negative value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_GetNapClientPid_003, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t expectedPid = -1;
    napProcess.napClientPid_ = expectedPid;
    int32_t actualPid = napProcess.GetNapClientPid();
    ASSERT_EQ(expectedPid, actualPid);
}

/**
 * @tc.name: NapProcessTest_NotifyNapOnline_002
 * @tc.desc: Test notify nap online and verify pid is set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_NotifyNapOnline_002, TestSize.Level1)
{
    NapProcess napProcess;
    int32_t result = napProcess.NotifyNapOnline();
    ASSERT_EQ(result, RET_OK);
    ASSERT_GE(napProcess.GetNapClientPid(), 0);
}

/**
 * @tc.name: NapProcessTest_RemoveInputEventObserver_002
 * @tc.desc: Test remove input event observer multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_RemoveInputEventObserver_002, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data;
    data.pid = 1;
    data.uid = 1;
    data.bundleName = "testBundle";
    napProcess.napMap_[data] = SUBSCRIBED;
    napProcess.napClientPid_ = 1234;
    
    int32_t ret = napProcess.RemoveInputEventObserver();
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(napProcess.napMap_.empty());
    ASSERT_EQ(napProcess.napClientPid_, REMOVE_OBSERVER);
    
    ret = napProcess.RemoveInputEventObserver();
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: NapProcessTest_GetAllMmiSubscribedEvents_003
 * @tc.desc: Test get all mmi subscribed events with multiple entries
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_GetAllMmiSubscribedEvents_003, TestSize.Level1)
{
    NapProcess napProcess;
    
    NapProcess::NapStatusData data1;
    data1.pid = 1;
    data1.uid = 1;
    data1.bundleName = "bundle1";
    napProcess.napMap_[data1] = SUBSCRIBED;
    
    NapProcess::NapStatusData data2;
    data2.pid = 2;
    data2.uid = 2;
    data2.bundleName = "bundle2";
    napProcess.napMap_[data2] = NAP_EVENT;
    
    NapProcess::NapStatusData data3;
    data3.pid = 3;
    data3.uid = 3;
    data3.bundleName = "bundle3";
    napProcess.napMap_[data3] = ACTIVE_EVENT;
    
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> datas;
    ASSERT_EQ(napProcess.GetAllMmiSubscribedEvents(datas), RET_OK);
    ASSERT_EQ(datas.size(), 3);
}

/**
 * @tc.name: NapProcessTest_GetAllMmiSubscribedEvents_004
 * @tc.desc: Test get all mmi subscribed events after clear
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_GetAllMmiSubscribedEvents_004, TestSize.Level1)
{
    NapProcess napProcess;
    NapProcess::NapStatusData data;
    data.pid = 1;
    data.uid = 1;
    data.bundleName = "bundleName";
    napProcess.napMap_[data] = SUBSCRIBED;
    
    napProcess.RemoveInputEventObserver();
    
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> datas;
    ASSERT_EQ(napProcess.GetAllMmiSubscribedEvents(datas), RET_OK);
    ASSERT_TRUE(datas.empty());
}

/**
 * @tc.name: NapProcessTest_Concurrent_001
 * @tc.desc: Test concurrent access to napMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NapProcessTest, NapProcessTest_Concurrent_001, TestSize.Level1)
{
    NapProcess napProcess;
    
    NapProcess::NapStatusData data1;
    data1.pid = 1;
    data1.uid = 1;
    data1.bundleName = "bundle1";
    
    NapProcess::NapStatusData data2;
    data2.pid = 2;
    data2.uid = 2;
    data2.bundleName = "bundle2";
    
    napProcess.AddMmiSubscribedEventData(data1, SUBSCRIBED);
    napProcess.AddMmiSubscribedEventData(data2, NAP_EVENT);
    
    ASSERT_TRUE(napProcess.IsNeedNotify(data1));
    ASSERT_TRUE(napProcess.IsNeedNotify(data2));
    
    std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> datas;
    ASSERT_EQ(napProcess.GetAllMmiSubscribedEvents(datas), RET_OK);
    ASSERT_EQ(datas.size(), 2);
}
} // namespace MMI
} // namespace OHOS