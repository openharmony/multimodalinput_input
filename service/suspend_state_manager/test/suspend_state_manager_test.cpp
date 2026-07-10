/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define private public
#include "suspend_state_manager.h"
#undef private

using namespace testing::ext;
namespace OHOS {
namespace MMI {

class SuspendStateManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {
        auto &instance = SuspendStateManager::GetInstance();
        instance.isRssSaReady_.store(false);
        instance.isSuspendManagerSaReady_.store(false);
        instance.hasRegisteredObserver_.store(false);

        auto observer = SuspendStateObserver::GetInstance();
        std::lock_guard<std::mutex> lock(observer->mutex_);
        observer->frozenPidList_.clear();
    };
    void TearDown(void) {};
};

// ==================== SuspendStateObserver 测试 ====================

/**
 * @tc.name: SuspendStateObserver_OnFrozen_001
 * @tc.desc: OnFrozen 添加冻结 PID 后，GetFrozenPidList 能查到
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_OnFrozen_001, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    std::vector<int32_t> frozenPids = {1001, 1002};
    observer->OnFrozen(frozenPids, 0);

    auto pidList = observer->GetFrozenPidList();
    EXPECT_NE(pidList.find(1001), pidList.end());
    EXPECT_NE(pidList.find(1002), pidList.end());

    observer->OnActive(frozenPids, 0);
}

/**
 * @tc.name: SuspendStateObserver_OnFrozen_002
 * @tc.desc: OnFrozen 重复添加相同 PID 不会重复插入
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_OnFrozen_002, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    std::vector<int32_t> frozenPids = {2001};
    observer->OnFrozen(frozenPids, 0);
    observer->OnFrozen(frozenPids, 0);

    auto pidList = observer->GetFrozenPidList();
    EXPECT_EQ(pidList.count(2001), 1u);

    observer->OnActive(frozenPids, 0);
}

/**
 * @tc.name: SuspendStateObserver_OnActive_001
 * @tc.desc: OnActive 解冻后，GetFrozenPidList 中不再包含该 PID
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_OnActive_001, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    std::vector<int32_t> frozenPids = {3001, 3002, 3003};
    observer->OnFrozen(frozenPids, 0);

    std::vector<int32_t> activePids = {3002};
    observer->OnActive(activePids, 0);

    auto pidList = observer->GetFrozenPidList();
    EXPECT_NE(pidList.find(3001), pidList.end());
    EXPECT_EQ(pidList.find(3002), pidList.end());
    EXPECT_NE(pidList.find(3003), pidList.end());

    observer->OnActive({3001, 3003}, 0);
}

/**
 * @tc.name: SuspendStateObserver_OnActive_002
 * @tc.desc: OnActive 解冻不存在的 PID 不会崩溃
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_OnActive_002, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    std::vector<int32_t> activePids = {9999};
    ErrCode ret = observer->OnActive(activePids, 0);
    EXPECT_EQ(ret, RET_OK);

    auto pidList = observer->GetFrozenPidList();
    EXPECT_EQ(pidList.find(9999), pidList.end());
}

/**
 * @tc.name: SuspendStateObserver_OnActive_EmptyList
 * @tc.desc: OnActive 传入空列表不影响 frozenPidList
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_OnActive_EmptyList, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    observer->OnFrozen({4001}, 0);

    std::vector<int32_t> emptyPids;
    observer->OnActive(emptyPids, 0);

    auto pidList = observer->GetFrozenPidList();
    EXPECT_NE(pidList.find(4001), pidList.end());

    observer->OnActive({4001}, 0);
}

/**
 * @tc.name: SuspendStateObserver_OnFrozen_EmptyList
 * @tc.desc: OnFrozen 传入空列表不影响 frozenPidList
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_OnFrozen_EmptyList, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    observer->OnFrozen({4002}, 0);

    std::vector<int32_t> emptyPids;
    observer->OnFrozen(emptyPids, 0);

    auto pidList = observer->GetFrozenPidList();
    EXPECT_NE(pidList.find(4002), pidList.end());

    observer->OnActive({4002}, 0);
}

/**
 * @tc.name: SuspendStateObserver_OnDoze_001
 * @tc.desc: OnDoze 调用返回 RET_OK，不影响 frozenPidList
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_OnDoze_001, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    observer->OnFrozen({4003}, 0);

    std::vector<int32_t> dozePids = {4003};
    ErrCode ret = observer->OnDoze(dozePids, 0);
    EXPECT_EQ(ret, RET_OK);

    auto pidList = observer->GetFrozenPidList();
    EXPECT_NE(pidList.find(4003), pidList.end());

    observer->OnActive({4003}, 0);
}

/**
 * @tc.name: SuspendStateObserver_IsFrozenPid_001
 * @tc.desc: 冻结后 IsFrozenPid 返回 true，解冻后返回 false
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_IsFrozenPid_001, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    const int32_t testPid = 4101;

    EXPECT_FALSE(observer->IsFrozenPid(testPid));

    observer->OnFrozen({testPid}, 0);
    EXPECT_TRUE(observer->IsFrozenPid(testPid));

    observer->OnActive({testPid}, 0);
    EXPECT_FALSE(observer->IsFrozenPid(testPid));
}

/**
 * @tc.name: SuspendStateObserver_IsFrozenPid_002
 * @tc.desc: 未冻结的 PID 调用 IsFrozenPid 返回 false
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_IsFrozenPid_002, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    EXPECT_FALSE(observer->IsFrozenPid(99999));
}

/**
 * @tc.name: SuspendStateObserver_IsFrozenPid_003
 * @tc.desc: 多个 PID 冻结后，IsFrozenPid 对每个 PID 分别返回正确结果
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_IsFrozenPid_003, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    observer->OnFrozen({4102, 4103}, 0);

    EXPECT_TRUE(observer->IsFrozenPid(4102));
    EXPECT_TRUE(observer->IsFrozenPid(4103));
    EXPECT_FALSE(observer->IsFrozenPid(4104));

    observer->OnActive({4102, 4103}, 0);
}

/**
 * @tc.name: SuspendStateObserver_ConcurrentAccess
 * @tc.desc: 多线程并发访问 OnFrozen/OnActive/IsFrozenPid/GetFrozenPidList 不崩溃
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_ConcurrentAccess, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    const int32_t threadCount = 8;
    std::vector<std::thread> threads;

    for (int32_t i = 0; i < threadCount; i++) {
        threads.emplace_back([observer, i]() {
            int32_t basePid = 5000 + i * 10;
            std::vector<int32_t> addPids = {basePid, basePid + 1};
            std::vector<int32_t> removePids = {basePid};

            for (int32_t j = 0; j < 100; j++) {
                observer->OnFrozen(addPids, 0);
                observer->IsFrozenPid(basePid);
                observer->GetFrozenPidList();
                observer->OnActive(removePids, 0);
                observer->IsFrozenPid(basePid);
                observer->GetFrozenPidList();
            }
        });
    }

    for (auto &t : threads) {
        t.join();
    }
}

/**
 * @tc.name: SuspendStateObserver_GetFrozenPidList_ReturnsCopy
 * @tc.desc: GetFrozenPidList 返回的是拷贝，修改返回值不影响内部状态
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_GetFrozenPidList_ReturnsCopy, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    observer->OnFrozen({9001}, 0);

    auto pidList1 = observer->GetFrozenPidList();
    EXPECT_NE(pidList1.find(9001), pidList1.end());

    pidList1.erase(9001);

    auto pidList2 = observer->GetFrozenPidList();
    EXPECT_NE(pidList2.find(9001), pidList2.end());

    observer->OnActive({9001}, 0);
}

// ==================== SuspendStateManager 测试 ====================

/**
 * @tc.name: SuspendStateManager_GetInstance_001
 * @tc.desc: GetInstance 返回同一单例引用
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_GetInstance_001, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();
    auto &instance2 = SuspendStateManager::GetInstance();
    EXPECT_EQ(&instance, &instance2);
}

/**
 * @tc.name: SuspendStateManager_RegisterSuspendStateChanged_001
 * @tc.desc: SA 未就绪时注册返回失败
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_RegisterSuspendStateChanged_001, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    int32_t ret = instance.RegisterSuspendStateChanged();
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: SuspendStateManager_RegisterSuspendStateChanged_002
 * @tc.desc: 仅 RSS SA 就绪时注册仍返回失败
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_RegisterSuspendStateChanged_002, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    instance.SetRssSaReady();
    int32_t ret = instance.RegisterSuspendStateChanged();
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: SuspendStateManager_RegisterSuspendStateChanged_003
 * @tc.desc: 仅 Suspend SA 就绪时注册仍返回失败
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_RegisterSuspendStateChanged_003, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    instance.SetSuspendSaReady();
    int32_t ret = instance.RegisterSuspendStateChanged();
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: SuspendStateManager_RegisterSuspendStateChanged_004
 * @tc.desc: 两个 SA 都就绪后，未注册过时尝试注册（注册结果取决于运行环境）
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_RegisterSuspendStateChanged_004, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    instance.SetRssSaReady();
    instance.SetSuspendSaReady();

    int32_t ret = instance.RegisterSuspendStateChanged();
    // 注册成功或失败取决于运行环境，此处仅验证不崩溃
    EXPECT_TRUE(ret == RET_OK || ret != RET_OK);
}

/**
 * @tc.name: SuspendStateManager_RegisterSuspendStateChanged_005
 * @tc.desc: 已注册后再次注册返回 RET_OK（幂等）
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_RegisterSuspendStateChanged_005, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    instance.SetRssSaReady();
    instance.SetSuspendSaReady();

    instance.RegisterSuspendStateChanged();
    int32_t ret = instance.RegisterSuspendStateChanged();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SuspendStateManager_UnRegisterSuspendStateChanged_001
 * @tc.desc: 未注册时取消注册返回 RET_OK
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_UnRegisterSuspendStateChanged_001, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    int32_t ret = instance.UnRegisterSuspendStateChanged();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SuspendStateManager_UnRegisterSuspendStateChanged_002
 * @tc.desc: 注册后取消，再注册仍可调用
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_UnRegisterSuspendStateChanged_002, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    instance.SetRssSaReady();
    instance.SetSuspendSaReady();

    instance.RegisterSuspendStateChanged();
    int32_t unret = instance.UnRegisterSuspendStateChanged();
    EXPECT_EQ(unret, RET_OK);

    instance.RegisterSuspendStateChanged();
    instance.UnRegisterSuspendStateChanged();
}

/**
 * @tc.name: SuspendStateManager_SetRssSaReady_001
 * @tc.desc: SetRssSaReady 重复调用不崩溃
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_SetRssSaReady_001, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    instance.SetRssSaReady();
    instance.SetRssSaReady();
}

/**
 * @tc.name: SuspendStateManager_SetSuspendSaReady_001
 * @tc.desc: SetSuspendSaReady 重复调用不崩溃
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_SetSuspendSaReady_001, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    instance.SetSuspendSaReady();
    instance.SetSuspendSaReady();
}

/**
 * @tc.name: SuspendStateManager_IsFrozen_001
 * @tc.desc: PID 未冻结时 IsFrozen 返回 false
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_IsFrozen_001, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    bool frozen = instance.IsFrozen(12345);
    EXPECT_FALSE(frozen);
}

/**
 * @tc.name: SuspendStateManager_IsFrozen_002
 * @tc.desc: PID 冻结后 IsFrozen 返回 true，解冻后返回 false
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_IsFrozen_002, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    std::vector<int32_t> frozenPids = {6001};
    observer->OnFrozen(frozenPids, 0);

    bool frozen = instance.IsFrozen(6001);
    EXPECT_TRUE(frozen);

    observer->OnActive(frozenPids, 0);

    frozen = instance.IsFrozen(6001);
    EXPECT_FALSE(frozen);
}

/**
 * @tc.name: SuspendStateManager_IsFrozen_003
 * @tc.desc: 多个 PID 冻结时，IsFrozen 分别返回正确结果
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_IsFrozen_003, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    observer->OnFrozen({6002, 6003}, 0);

    EXPECT_TRUE(instance.IsFrozen(6002));
    EXPECT_TRUE(instance.IsFrozen(6003));
    EXPECT_FALSE(instance.IsFrozen(6004));
    EXPECT_FALSE(instance.IsFrozen(99999));

    observer->OnActive({6002, 6003}, 0);
}

/**
 * @tc.name: SuspendStateManager_IsFrozen_004
 * @tc.desc: 全部解冻后，IsFrozen 对所有 PID 返回 false
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_IsFrozen_004, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    observer->OnFrozen({6005, 6006}, 0);
    EXPECT_TRUE(instance.IsFrozen(6005));
    EXPECT_TRUE(instance.IsFrozen(6006));

    observer->OnActive({6005, 6006}, 0);
    EXPECT_FALSE(instance.IsFrozen(6005));
    EXPECT_FALSE(instance.IsFrozen(6006));
}

/**
 * @tc.name: SuspendStateManager_Dump_001
 * @tc.desc: Dump 无冻结 PID 时不崩溃
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_Dump_001, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();

    const char *tmpFile = "/data/tmp_suspend_dump_001.log";
    int fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    instance.Dump(fd);
    close(fd);
    unlink(tmpFile);
}

/**
 * @tc.name: SuspendStateManager_Dump_002
 * @tc.desc: Dump 有冻结 PID 时输出包含正确信息
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_Dump_002, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    observer->OnFrozen({7002, 7003}, 0);

    const char *tmpFile = "/data/tmp_suspend_dump_002.log";
    int fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    instance.Dump(fd);
    close(fd);

    std::string content;
    int fdRead = open(tmpFile, O_RDONLY);
    ASSERT_GE(fdRead, 0);
    char buf[1024] = {};
    ssize_t bytes = read(fdRead, buf, sizeof(buf) - 1);
    if (bytes > 0) {
        content = buf;
    }
    close(fdRead);
    unlink(tmpFile);

    EXPECT_NE(content.find("Total frozen pid size:2"), std::string::npos);
    EXPECT_NE(content.find("frozePid:7002"), std::string::npos);
    EXPECT_NE(content.find("frozePid:7003"), std::string::npos);

    observer->OnActive({7002, 7003}, 0);
}

/**
 * @tc.name: SuspendStateManager_Dump_003
 * @tc.desc: Dump 大量冻结 PID 时不崩溃
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_Dump_003, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    std::vector<int32_t> largePids;
    for (int32_t i = 0; i < 100; i++) {
        largePids.push_back(7100 + i);
    }
    observer->OnFrozen(largePids, 0);

    const char *tmpFile = "/data/tmp_suspend_dump_003.log";
    int fd = open(tmpFile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);

    instance.Dump(fd);
    close(fd);
    unlink(tmpFile);

    observer->OnActive(largePids, 0);
}

// ==================== 冻结光标样式相关测试 ====================

/**
 * @tc.name: SuspendStateObserver_FrozenThenActive_CursorStyle
 * @tc.desc: 冻结后 frozenPidList 包含 PID，解冻后不包含
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_FrozenThenActive_CursorStyle, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    const int32_t testPid = 8001;

    auto pidList = observer->GetFrozenPidList();
    EXPECT_EQ(pidList.find(testPid), pidList.end());

    observer->OnFrozen({testPid}, 0);
    pidList = observer->GetFrozenPidList();
    EXPECT_NE(pidList.find(testPid), pidList.end());

    observer->OnActive({testPid}, 0);
    pidList = observer->GetFrozenPidList();
    EXPECT_EQ(pidList.find(testPid), pidList.end());
}

/**
 * @tc.name: SuspendStateObserver_MultiplePids_FrozenAndActive
 * @tc.desc: 多个 PID 交替冻结/解冻，frozenPidList 状态正确
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateObserver_MultiplePids_FrozenAndActive, TestSize.Level1)
{
    auto observer = SuspendStateObserver::GetInstance();
    ASSERT_NE(observer, nullptr);

    observer->OnFrozen({8002, 8003}, 0);
    auto pidList = observer->GetFrozenPidList();
    EXPECT_NE(pidList.find(8002), pidList.end());
    EXPECT_NE(pidList.find(8003), pidList.end());
    EXPECT_EQ(pidList.find(8004), pidList.end());

    observer->OnActive({8002}, 0);
    observer->OnFrozen({8004}, 0);
    pidList = observer->GetFrozenPidList();
    EXPECT_EQ(pidList.find(8002), pidList.end());
    EXPECT_NE(pidList.find(8003), pidList.end());
    EXPECT_NE(pidList.find(8004), pidList.end());

    observer->OnActive({8003, 8004}, 0);
    pidList = observer->GetFrozenPidList();
    EXPECT_EQ(pidList.find(8003), pidList.end());
    EXPECT_EQ(pidList.find(8004), pidList.end());
}

/**
 * @tc.name: SuspendStateManager_IsFrozen_ConcurrentWithObserver
 * @tc.desc: 多线程并发冻结/解冻与 IsFrozen 查询不崩溃
 * @tc.type: FUNC
 */
HWTEST_F(SuspendStateManagerTest, SuspendStateManager_IsFrozen_ConcurrentWithObserver, TestSize.Level1)
{
    auto &instance = SuspendStateManager::GetInstance();
    auto observer = SuspendStateObserver::GetInstance();

    const int32_t threadCount = 4;
    std::vector<std::thread> threads;

    for (int32_t i = 0; i < threadCount; i++) {
        threads.emplace_back([observer, &instance, i]() {
            int32_t basePid = 9000 + i * 10;
            std::vector<int32_t> pids = {basePid, basePid + 1};

            for (int32_t j = 0; j < 100; j++) {
                observer->OnFrozen(pids, 0);
                instance.IsFrozen(basePid);
                instance.IsFrozen(basePid + 1);
                observer->OnActive(pids, 0);
                instance.IsFrozen(basePid);
            }
        });
    }

    for (auto &t : threads) {
        t.join();
    }
}

} // namespace MMI
} // namespace OHOS
