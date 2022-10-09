/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef EVENT_TEST_UTIL_H
#define EVENT_TEST_UTIL_H

#include <chrono>
#include <condition_variable>
#include <list>
#include <mutex>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "input_manager.h"
#include "singleton.h"
#include "window_utils_test.h"

namespace OHOS {
namespace MMI {
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;
namespace {
using namespace testing::ext;
PermissionDef infoManagerTestPermDef_ = {
    .permissionName = "ohos.permission.INPUT_MONITORING",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "test input agent",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL
};

PermissionStateFull infoManagerTestState_ = {
    .grantFlags = {1},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .isGeneral = true,
    .permissionName = "ohos.permission.INPUT_MONITORING",
    .resDeviceID = {"local"}
};

HapPolicyParams infoManagerTestPolicyPrams_ = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {infoManagerTestPermDef_},
    .permStateList = {infoManagerTestState_}
};

HapInfoParams infoManagerTestInfoParms_ = {
    .bundleName = "inputManager_test",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "InputManagerTest"
};
} // namespace
enum class TestScene : int32_t {
    NORMAL_TEST = 0,
    EXCEPTION_TEST,
};

enum class RECV_FLAG : uint32_t {
    RECV_FOCUS = 0x00000000,
    RECV_MONITOR,
    RECV_INTERCEPT,
    RECV_MARK_CONSUMED,
};

class EventUtilTest final {
    DECLARE_DELAYED_SINGLETON(EventUtilTest);
public:
    DISALLOW_COPY_AND_MOVE(EventUtilTest);
    bool Init();
    std::string GetEventDump();
    void AddEventDump(std::string eventDump);
    std::string DumpInputEvent(const std::shared_ptr<PointerEvent>& pointerEvent);
    std::string DumpInputEvent(const std::shared_ptr<KeyEvent>& keyEvent);
    bool CompareDump(const std::shared_ptr<PointerEvent>& pointerEvent);
    bool CompareDump(const std::shared_ptr<KeyEvent>& keyEvent);
public:
    inline RECV_FLAG GetRecvFlag()
    {
        return recvFlag_;
    }
    inline void SetRecvFlag(RECV_FLAG flag)
    {
        recvFlag_ = flag;
    }
private:
    RECV_FLAG recvFlag_ { RECV_FLAG::RECV_FOCUS };
    std::mutex mutex_;
    std::list<std::string> strEventDump_;
    std::condition_variable conditionVariable_;
};

#define TestUtil ::OHOS::DelayedSingleton<EventUtilTest>::GetInstance()

class InputEventConsumer : public IInputEventConsumer {
public:
    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {};
};

class InputEventCallback : public IInputEventConsumer {
public:
    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {};
    int32_t GetLastEventId() const;

private:
    mutable int32_t lastPointerEventId_ { -1 };
};

inline int32_t InputEventCallback::GetLastEventId() const
{
    return lastPointerEventId_;
}

class WindowEventConsumer : public IInputEventConsumer {
public:
    virtual void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override;
    virtual void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {};
    uint64_t GetConsumerThreadId();
private:
    mutable uint64_t threadId_ { 0 };
};

int64_t GetNanoTime();
template<typename sharedType>
std::shared_ptr<sharedType> GetPtr()
{
    return std::make_shared<sharedType>();
}

template<typename EventType>
void TestSimulateInputEvent(EventType& event, const TestScene& testScene = TestScene::NORMAL_TEST)
{
    EXPECT_TRUE((static_cast<int32_t>(testScene) ^ TestUtil->CompareDump(event)));
}
void DumpWindowData(const std::shared_ptr<PointerEvent>& pointerEvent);
class AccessMonitor {
public:
    AccessMonitor()
    {
        currentId_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = { 0 };
        tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms_, infoManagerTestPolicyPrams_);
        monitorId_ = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(monitorId_);
    }
    ~AccessMonitor()
    {
        AccessTokenKit::DeleteToken(monitorId_);
        SetSelfTokenID(currentId_);
    }
private:
    AccessTokenID currentId_ { 0 };
    AccessTokenID monitorId_ { 0 };
};
} // namespace MMI
} // namespace OHOS

#endif // EVENT_TEST_UTIL_H