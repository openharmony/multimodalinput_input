/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <semaphore.h>
#include <sys/types.h>

#include <csignal>
#include <cstdio>
#include <iostream>
#include <gtest/gtest.h>
#include <regex>
#include <set>
#include <sstream>

#include "accesstoken_kit.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_handler_manager.h"
#include "input_manager.h"
#include "multimodal_event_handler.h"
#include "nativetoken_kit.h"
#include "pointer_event.h"
#include "proto.h"
#include "token_setproc.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerFilterManualTest"

namespace OHOS {
namespace MMI {
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;
namespace {
using namespace testing::ext;
static const int32_t SIG_KILL = 9;
static constexpr int32_t DEFAULT_API_VERSION = 8;

HapInfoParams infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "inputManagerFilterManualTest",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = DEFAULT_API_VERSION,
    .isSystemApp = true
};

PermissionDef infoManagerTestPermDef = {
    .permissionName = "ohos.permission.test",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_SYSTEM_CORE,
    .label = "label",
    .labelId = 1,
    .description = "test filter",
    .descriptionId = 1,
};

PermissionDef infoManagerTestPermDefDump = {
    .permissionName = "ohos.permission.DUMP",
    .bundleName = "inputManagerFilterManualTest",
    .grantMode = 1,
    .availableLevel = APL_SYSTEM_CORE,
    .label = "label",
    .labelId = 1,
    .description = "test filter",
    .descriptionId = 1,
};

PermissionStateFull infoManagerTestState = {
    .permissionName = "ohos.permission.test",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 1 },
};

PermissionStateFull infoManagerTestStateDump = {
    .permissionName = "ohos.permission.DUMP",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 1 },
};

HapPolicyParams infoManagerTestPolicyPrams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = { infoManagerTestPermDef, infoManagerTestPermDefDump },
    .permStateList = { infoManagerTestState, infoManagerTestStateDump }
};
} // namespace

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms, infoManagerTestPolicyPrams);
        accessID_ = tokenIdEx.tokenIDEx;
        SetSelfTokenID(accessID_);
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
    }

private:
    uint64_t currentID_;
    uint64_t accessID_ = 0;
};

class InputManagerFilterManualTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() {}
    void TearDown() {}
    pid_t GetMmiServerPid() const
    {
        const std::string mmiServerProcessName = "multimodalinput";
        return GetProcessPidByName(mmiServerProcessName.c_str());
    }
    int32_t StopExecutable(pid_t pid) const
    {
        if (pid != INVALID_PID) {
            MMI_HILOGI("Kill pid = %{public}d, before", pid);
            kill(pid, SIG_KILL);
            MMI_HILOGI("Kill pid = %{public}d, finished", pid);
        }
        return RET_OK;
    }
    pid_t GetProcessPidByName(const char *procName) const
    {
        pid_t pid = getpid();
        FILE *fp;
        int32_t buffSize = 255;
        char buf[buffSize];
        std::string cmd = "pidof " + std::string(procName);
        MMI_HILOGI("The cmd:%{public}s", cmd.c_str());
        if ((fp = popen(cmd.c_str(), "r")) != nullptr) {
            if (fgets(buf, buffSize, fp) != nullptr) {
                pid = atoi(buf);
            }
        }
        pclose(fp);
        return pid;
    }
    int32_t GetSelfHidumperFilterNum() const
    {
        std::set<std::pair<std::string, std::string>> info;
        auto ret = GetSelfHidumperFilter(info);
        if (ret != RET_OK) {
            return 0;
        }
        return info.size();
    }
    int32_t GetSelfHidumperFilter(std::set<std::pair<std::string, std::string>> &info) const
    {
        const char *cmd = "hidumper -s 3101 -a -f";
        FILE *fp = popen(cmd, "r");
        if (fp == nullptr) {
            MMI_HILOGE("Call popen fail, cmd:%{public}s", cmd);
            return RET_ERR;
        }
        pid_t pid = getpid();
        std::string strPid = std::to_string(pid);
        MMI_HILOGE("Self pid:%{public}s", strPid.c_str());
        std::regex itemRegex("priority:(\\d+) \\| filterId:(\\d+) \\| Pid:(\\d+)\r?\n?");
        char *buf = nullptr;
        size_t bufLen = 0;
        ssize_t nRead = 0;
        uint64_t matchSize = 4;
        while ((nRead = getline(&buf, &bufLen, fp)) != -1) {
            std::string line(buf);
            std::smatch match;
            if (!std::regex_match(line, match, itemRegex)) {
                MMI_HILOGI("Not match line:%{public}s", line.c_str());
                continue;
            }
            MMI_HILOGI("Line match:%{public}s", line.c_str());
            if (match.size() != matchSize) {
                MMI_HILOGI("Check itemRegex, it is error");
                continue;
            }
            std::string priority = match[1].str();
            std::string filterId = match[2].str();
            std::string pidStr = match[3].str();
            if (pidStr != strPid) {
                continue;
            }
            auto ret = info.emplace(std::make_pair(priority, filterId));
            if (!ret.second) {
                MMI_HILOGE("Duplicate priority:%{public}s, filterId:%{public}s,", priority.c_str(), filterId.c_str());
            }
            info.insert(std::make_pair(priority, filterId));
        };
        if (buf != nullptr) {
            free(buf);
            buf = nullptr;
        }
        if (fp != nullptr) {
            pclose(fp);
            fp = nullptr;
        }
        return RET_OK;
    }
};

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
/**
 * @tc.name: HandlePointerEventFilter_001
 * @tc.desc: Verify pointer event filter
 * @tc.type: FUNC
 * @tc.require:
 */
struct PointerFilter : public IInputEventFilter {
    const int32_t exceptX;
    const int32_t exceptY;
    sem_t &sem;
    bool &result;
    PointerFilter(int32_t exceptX, int32_t exceptY, sem_t &sem, bool &result)
        : exceptX(exceptX), exceptY(exceptY), sem(sem), result(result)
    {}
    virtual bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
    {
        return false;
    }
    bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        MMI_HILOGD("Callback enter");
        result = false;
        do {
            CHKPB(pointerEvent);
            const std::vector<int32_t> ids = pointerEvent->GetPointerIds();
            if (ids.empty()) {
                MMI_HILOGE("The ids is empty");
                break;
            }
            const int32_t firstPointerId = ids[0];
            PointerEvent::PointerItem item;
            if (!pointerEvent->GetPointerItem(firstPointerId, item)) {
                MMI_HILOGE("GetPointerItem:%{public}d fail", firstPointerId);
                break;
            }
            const int32_t x = item.GetDisplayX();
            const int32_t y = item.GetDisplayY();
            if (x == exceptX && y == exceptY) {
                MMI_HILOGI(
                    "The values of X and y are both 10, which meets the expectation and callbackRet is set to 1");
                result = true;
                break;
            }
            MMI_HILOGI("The values of X and y are not 10, which meets the expectation and callbackRet is set to 2");
        } while (0);
        int32_t ret = sem_post(&sem);
        EXPECT_EQ(ret, 0);
        return result;
    }
};
void Simulate(int32_t x, int32_t y)
{
    const int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetDisplayX(x);
    item.SetDisplayY(y);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(pointerId);
    MMI_HILOGI("SimulateInputEvent begin");
    InputManager::GetInstance()->SimulateInputEvent(pointerEvent);
    MMI_HILOGI("SimulateInputEvent finished");
}
void WaitPointerEnd(sem_t &sem)
{
    struct timespec ts;
    int32_t ret = clock_gettime(CLOCK_REALTIME, &ts);
    ASSERT_NE(ret, -1);
    int32_t waitForSeconds = 3;
    ts.tv_sec += waitForSeconds;
    ret = sem_timedwait(&sem, &ts);
    ASSERT_NE(ret, 0);
}
HWTEST_F(InputManagerFilterManualTest, HandlePointerEventFilter_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("Enter HandlePointerEventFilter_001");
    sem_t sem;
    int32_t ret = sem_init(&sem, 0, 0);
    ASSERT_EQ(ret, 0);
    bool result = false;
    auto filter = std::make_shared<PointerFilter>(10, 10, sem, result);
    const int32_t priority = 201;
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    const int32_t filterId = InputManager::GetInstance()->AddInputEventFilter(filter, priority, touchTags);
    ASSERT_NE(filterId, -1);
    ASSERT_EQ(GetSelfHidumperFilterNum(), 1);

    // set physical x and physical y are 10, will expect value is 1
    Simulate(10, 10);
    WaitPointerEnd(sem);
    ASSERT_EQ(result, true);
    // set physical x and physical y are not 10, will expect value is 2
    Simulate(0, 0);
    WaitPointerEnd(sem);
    ASSERT_EQ(result, false);
    auto retCode = InputManager::GetInstance()->RemoveInputEventFilter(filterId);
    ASSERT_EQ(retCode, RET_OK);
    ASSERT_EQ(GetSelfHidumperFilterNum(), 0);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: HandlePointerEventFilter_002
 * @tc.desc: Verify key event filter
 * @tc.type: FUNC
 * @tc.require:
 */
struct KeyFilter002 : public IInputEventFilter {
    const int32_t exceptKeyCode;
    sem_t &sem;
    bool &result;
    KeyFilter002(int32_t exceptKeyCode, sem_t &sem, bool &result)
        : exceptKeyCode(exceptKeyCode), sem(sem), result(result)
    {}
    bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
    {
        MMI_HILOGI("KeyFilter::OnInputEvent enter, pid:%{public}d, exceptKeyCode:%{public}d", getpid(),
            exceptKeyCode);
        do {
            result = false;
            CHKPB(keyEvent);
            auto keyCode = keyEvent->GetKeyCode();
            MMI_HILOGI("KeyFilter::OnInputEvent receive keyCode:%{private}d return true", keyCode);
            if (keyCode == exceptKeyCode) {
                result = true;
                break;
            }
        } while (0);
        int32_t ret = sem_post(&sem);
        EXPECT_EQ(ret, 0);
        return result;
    }
    bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        return false;
    }
};
void WaitKeyEnd(sem_t &sem)
{
    struct timespec ts;
    int32_t ret = clock_gettime(CLOCK_REALTIME, &ts);
    ASSERT_NE(ret, -1);
    int32_t waitForSeconds = 5;
    ts.tv_sec += waitForSeconds;
    ret = sem_timedwait(&sem, &ts);
    ASSERT_EQ(ret, 0);
}
void SimulateKeyEvent(bool &resultA, bool &resultB, const int32_t KEYCODE, bool isKeyAEvent, sem_t &sem)
{
    auto keyEventSample = KeyEvent::Create();
    ASSERT_NE(keyEventSample, nullptr);
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KEYCODE);
    kitDown.SetPressed(true);
    kitDown.SetDeviceId(1);
    keyEventSample->SetKeyCode(KEYCODE);
    keyEventSample->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEventSample->AddPressedKeyItems(kitDown);
    if (isKeyAEvent) {
        MMI_HILOGI("SimulateInputEvent key event KEYCODE_A(2017)");
        InputManager::GetInstance()->SimulateInputEvent(keyEventSample);
        WaitKeyEnd(sem);
        ASSERT_EQ(resultA, true);
        ASSERT_EQ(resultB, false);
    } else {
        MMI_HILOGI("SimulateInputEvent key event KEYCODE_B(2018)");
        InputManager::GetInstance()->SimulateInputEvent(keyEventSample);
        WaitKeyEnd(sem);
        ASSERT_EQ(resultA, false);
        ASSERT_EQ(resultB, true);
    }
}
HWTEST_F(InputManagerFilterManualTest, HandleKeyEventFilter_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("Enter HandlePointerEventFilter_002");
    ASSERT_NE(GetSelfHidumperFilterNum(), 0);

    sem_t semA;
    int32_t ret = sem_init(&semA, 0, 0);
    ASSERT_EQ(ret, 0);
    bool resultA = false;
    auto filterA = std::make_shared<KeyFilter002>(KeyEvent::KEYCODE_A, semA, resultA);
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    const int32_t filterIdA = InputManager::GetInstance()->AddInputEventFilter(filterA, 220, touchTags);
    ASSERT_NE(filterIdA, RET_ERR);

    sem_t semB;
    ret = sem_init(&semB, 0, 0);
    ASSERT_EQ(ret, 0);
    bool resultB = false;
    auto filterB = std::make_shared<KeyFilter002>(KeyEvent::KEYCODE_B, semB, resultB);
    const int32_t filterIdB = InputManager::GetInstance()->AddInputEventFilter(filterB, 210, touchTags);
    ASSERT_NE(filterIdB, RET_ERR);
    ASSERT_EQ(GetSelfHidumperFilterNum(), 2);

    resultA = false;
    resultB = false;
    SimulateKeyEvent(resultA, resultB, KeyEvent::KEYCODE_A, true, semA);
    resultA = false;
    resultB = false;
    SimulateKeyEvent(resultA, resultB, KeyEvent::KEYCODE_B, false, semB);

    auto retCode = InputManager::GetInstance()->RemoveInputEventFilter(filterIdA);
    ASSERT_EQ(retCode, RET_OK);
    ASSERT_EQ(GetSelfHidumperFilterNum(), 1);
    retCode = InputManager::GetInstance()->RemoveInputEventFilter(filterIdB);
    ASSERT_EQ(retCode, RET_OK);
    ASSERT_EQ(GetSelfHidumperFilterNum(), 0);
}

/**
 * @tc.name: HandlePointerEventFilter_002
 * @tc.desc: Max filter number check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerFilterManualTest, HandleKeyEventFilter_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("Enter HandlePointerEventFilter_003");
    struct KeyFilter : public IInputEventFilter {
        bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
        {
            MMI_HILOGI("KeyFilter::OnInputEvent enter, pid:%{public}d", getpid());
            return false;
        }
        bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
        {
            return false;
        }
    };
    auto addFilter = []() -> int32_t {
        auto filter = std::make_shared<KeyFilter>();
        uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
        const int32_t filterId = InputManager::GetInstance()->AddInputEventFilter(filter, 220, touchTags);
        return filterId;
    };
    ASSERT_NE(GetSelfHidumperFilterNum(), 0);
    const size_t testMaxNum = 10;
    const size_t singleClientSuportMaxNum = 4;
    std::vector<int32_t> filterIds;
    for (size_t i = 0; i < testMaxNum; ++i) {
        const int32_t filterId = addFilter();
        if (i < singleClientSuportMaxNum) {
            ASSERT_NE(filterId, RET_ERR);
            filterIds.push_back(filterId);
        } else {
            ASSERT_EQ(filterId, RET_ERR);
        }
    }
    ASSERT_EQ(filterIds.size(), singleClientSuportMaxNum);
    ASSERT_EQ(GetSelfHidumperFilterNum(), singleClientSuportMaxNum);

    int32_t cnt = singleClientSuportMaxNum;
    for (auto &filterId : filterIds) {
        auto retCode = InputManager::GetInstance()->RemoveInputEventFilter(filterId);
        ASSERT_EQ(retCode, RET_OK);
        --cnt;
        ASSERT_EQ(GetSelfHidumperFilterNum(), cnt);
    }
    ASSERT_EQ(GetSelfHidumperFilterNum(), 0);
}

/**
 * @tc.name: HandlePointerEventFilter_004
 * @tc.desc: Add filter but not remove filter, depend on process dead auto kill
 * @tc.type: FUNC
 * @tc.require:
 */
/**
 * HWTEST_F(InputManagerFilterManualTest, DISABLED_HandleKeyEventFilter_004, TestSize.Level1)
 * {
 *     CALL_DEBUG_ENTER;
 *     MMI_HILOGI("enter DISABLED_HandleKeyEventFilter_004");
 *     struct KeyFilter : public IInputEventFilter {
 *         bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
 *         {
 *             MMI_HILOGI("KeyFilter::OnInputEvent enter, pid:%{public}d", getpid());
 *             return false;
 *         }
 *         bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
 *         {
 *             return false;
 *         }
 *     };
 *     AccessToken accessToken;
 *     auto addFilter = []() -> int32_t {
 *         auto filter = std::make_shared<KeyFilter>();
 *         uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
 *         const int32_t filterId = InputManager::GetInstance()->AddInputEventFilter(filter, 220, touchTags);
 *         return filterId;
 *     };
 *     const size_t singleClientSuportMaxNum = 4;
 *     for (size_t i = 0; i < singleClientSuportMaxNum; ++i) {
 *         const int32_t filterId = addFilter();
 *         ASSERT_NE(filterId, RET_ERR);
 *     }
 *     ASSERT_EQ(GetSelfHidumperFilterNum(), singleClientSuportMaxNum);
 * }
 */

/**
 * @tc.name: HandlePointerEventFilter_005
 * @tc.desc: Delete all filter of this process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerFilterManualTest, HandleKeyEventFilter_005, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGI("Enter HandleKeyEventFilter_005");
    struct KeyFilter : public IInputEventFilter {
        bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
        {
            MMI_HILOGI("KeyFilter::OnInputEvent enter, pid:%{public}d", getpid());
            return false;
        }
        bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
        {
            return false;
        }
    };
    auto addFilter = []() -> int32_t {
        auto filter = std::make_shared<KeyFilter>();
        uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
        const int32_t filterId = InputManager::GetInstance()->AddInputEventFilter(filter, 220, touchTags);
        return filterId;
    };
    ASSERT_NE(GetSelfHidumperFilterNum(), 0);
    const size_t singleClientSuportMaxNum = 4;
    for (size_t i = 0; i < singleClientSuportMaxNum; ++i) {
        const int32_t filterId = addFilter();
        ASSERT_NE(filterId, RET_ERR);
    }
    ASSERT_EQ(GetSelfHidumperFilterNum(), singleClientSuportMaxNum);
    auto ret = InputManager::GetInstance()->RemoveInputEventFilter(-1);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_EQ(GetSelfHidumperFilterNum(), 0);
}

/**
 * @tc.name: HandlePointerEventFilter_006
 * @tc.desc: After add the filter, the mmi client does not exit the reset mmi server
 * @tc.type: FUNC
 * @tc.require:
 */
struct KeyFilter006 : public IInputEventFilter {
    bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
    {
        MMI_HILOGI("KeyFilter::OnInputEvent enter, pid:%{public}d", getpid());
        return false;
    }
    bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        return false;
    }
};
int32_t AddFilter()
{
    auto filter = std::make_shared<KeyFilter006>();
    uint32_t touchTags = CapabilityToTags(InputDeviceCapability::INPUT_DEV_CAP_MAX);
    const int32_t filterId = InputManager::GetInstance()->AddInputEventFilter(filter, 220, touchTags);
    return filterId;
}
void PrintFilter(const std::string title, const std::set<std::pair<std::string, std::string>> &s)
{
    MMI_HILOGI("The title:%{public}s, size:%{public}zu", title.c_str(), s.size());
    for (const auto &[priority, filterId] : s) {
        MMI_HILOGI("The priority:%{public}s, filterId:%{pulbic}s", priority.c_str(), filterId.c_str());
    }
};

/**
 * HWTEST_F(InputManagerFilterManualTest, HandleKeyEventFilter_006, TestSize.Level1)
 * {
 *     CALL_DEBUG_ENTER;
 *     MMI_HILOGI("enter HandleKeyEventFilter_006");
 *     AccessToken accessToken;
 *     const size_t singleClientSuportMaxNum = 4;
 *     for (size_t i = 0; i < singleClientSuportMaxNum; ++i) {
 *         const int32_t filterId = AddFilter();
 *         ASSERT_NE(filterId, RET_ERR);
 *     }
 *     pid_t serverPid1 = GetMmiServerPid();
 *     ASSERT_NE(serverPid1, -1);
 *     MMI_HILOGI("Origin serverPid1:%{public}d", serverPid1);
 *     std::set<std::pair<std::string, std::string>> filterInfo1;
 *     auto ret = GetSelfHidumperFilter(filterInfo1);
 *     ASSERT_EQ(ret, RET_OK);
 *     ret = StopExecutable(serverPid1);
 *     ASSERT_EQ(ret, RET_OK);
 *     pid_t serverPid2 = -1;
 *     int32_t cnt = 20;
 *     do {
 *         MMI_HILOGI("Sleep 1s, wait mmi server started, cnt:%{public}d", cnt--);
 *         sleep(1);
 *         serverPid2 = GetMmiServerPid();
 *         MMI_HILOGI("ServerPid2:%{public}d", serverPid2);
 *     } while (serverPid2 == -1);
 *     ASSERT_NE(serverPid2, -1);
 *     sleep(1);
 *     cnt = 20;
 *     bool retInitClient = false;
 *     do {
 *         MMI_HILOGI("Sleep 1s, wait init client success cnt:%{public}d", cnt--);
 *         sleep(1);
 *         --cnt;
 *         retInitClient = MMIEventHdl.InitClient();
 *     } while (cnt > 0 && !retInitClient);
 *     ASSERT_EQ(retInitClient, true);
 *     std::set<std::pair<std::string, std::string>> filterInfo2;
 *     cnt = 20;
 *     do {
 *         MMI_HILOGI("Sleep 1s, wait add filter finished, cnt:%{public}d", cnt--);
 *         sleep(1);
 *         filterInfo2.clear();
 *         GetSelfHidumperFilter(filterInfo2);
 *     } while (cnt > 0 && filterInfo1.size() != filterInfo2.size());
 *     PrintFilter("filterInfo1", filterInfo1);
 *     PrintFilter("filterInfo2", filterInfo2);
 *     ASSERT_TRUE(filterInfo1 == filterInfo2);
 * }
 */
#endif // OHOS_BUILD_ENABLE_KEYBOARD
} // namespace MMI
} // namespace OHOS