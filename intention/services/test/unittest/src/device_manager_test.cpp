/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "device_manager_test.h"

#include <unistd.h>

#undef LOG_TAG
#define LOG_TAG "IntentionDeviceManagerTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

using namespace testing::ext;
namespace {
struct device_status_epoll_event {
    int32_t fd { -1 };
    EpollEventType event_type { EPOLL_EVENT_BEGIN };
};

ContextService *g_instance = nullptr;
constexpr int32_t TIME_WAIT_FOR_OP_MS { 100 };
constexpr int32_t DEFAULT_WAIT_TIME_MS { 1000 };
constexpr int32_t WAIT_FOR_ONCE { 1 };
constexpr int32_t MAX_N_RETRIES { 100 };
const std::string TEST_DEV_NODE { "/dev/input/TestDeviceNode" };
} // namespace

ContextService::ContextService()
{
    FI_HILOGI("OHOS_BUILD_ENABLE_INTENTION_FRAMEWORK is on");
    OnStart();
}

ContextService::~ContextService()
{
    OnStop();
}

IDelegateTasks& ContextService::GetDelegateTasks()
{
    return delegateTasks_;
}

IDeviceManager& ContextService::GetDeviceManager()
{
    return devMgr_;
}

ITimerManager& ContextService::GetTimerManager()
{
    return timerMgr_;
}

IDragManager& ContextService::GetDragManager()
{
    return dragMgr_;
}

ContextService* ContextService::GetInstance()
{
    static std::once_flag flag;
    std::call_once(flag, [&]() {
        ContextService *cooContext = new (std::nothrow) ContextService();
        CHKPL(cooContext);
        g_instance = cooContext;
    });
    return g_instance;
}

ISocketSessionManager& ContextService::GetSocketSessionManager()
{
    return socketSessionMgr_;
}

IPluginManager& ContextService::GetPluginManager()
{
    return *pluginMgr_;
}

IInputAdapter& ContextService::GetInput()
{
    return *input_;
}

IDSoftbusAdapter& ContextService::GetDSoftbus()
{
    return *dsoftbusAda_;
}

bool ContextService::Init()
{
    CALL_DEBUG_ENTER;
    if (EpollCreate() != RET_OK) {
        FI_HILOGE("Create epoll failed");
        return false;
    }
    if (InitDelegateTasks() != RET_OK) {
        FI_HILOGE("Delegate tasks init failed");
        goto INIT_FAIL;
    }
    if (InitTimerMgr() != RET_OK) {
        FI_HILOGE("TimerMgr init failed");
        goto INIT_FAIL;
    }
    if (InitDevMgr() != RET_OK) {
        FI_HILOGE("DevMgr init failed");
        goto INIT_FAIL;
    }

    return true;

INIT_FAIL:
    EpollClose();
    return false;
}
int32_t ContextService::InitDevMgr()
{
    CALL_DEBUG_ENTER;
    int32_t ret = devMgr_.Init(this);
    if (ret != RET_OK) {
        FI_HILOGE("DevMgr init failed");
        return ret;
    }
    return ret;
}

int32_t ContextService::InitTimerMgr()
{
    CALL_DEBUG_ENTER;
    int32_t ret = timerMgr_.Init(this);
    if (ret != RET_OK) {
        FI_HILOGE("TimerMgr init failed");
        return ret;
    }

    ret = AddEpoll(EPOLL_EVENT_TIMER, timerMgr_.GetTimerFd());
    if (ret != RET_OK) {
        FI_HILOGE("AddEpoll for timer failed");
    }
    return ret;
}

int32_t ContextService::InitDelegateTasks()
{
    CALL_DEBUG_ENTER;
    if (!delegateTasks_.Init()) {
        FI_HILOGE("The delegate task init failed");
        return RET_ERR;
    }
    int32_t ret = AddEpoll(EPOLL_EVENT_ETASK, delegateTasks_.GetReadFd());
    if (ret != RET_OK) {
        FI_HILOGE("AddEpoll error ret:%{public}d", ret);
    }
    FI_HILOGI("AddEpoll, epollfd:%{public}d, fd:%{public}d", epollFd_, delegateTasks_.GetReadFd());
    return ret;
}

int32_t ContextService::EpollCreate()
{
    CALL_DEBUG_ENTER;
    epollFd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epollFd_ < 0) {
        FI_HILOGE("epoll_create1 failed:%{public}s", ::strerror(errno));
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ContextService::AddEpoll(EpollEventType type, int32_t fd)
{
    CALL_DEBUG_ENTER;
    if (!(type >= EPOLL_EVENT_BEGIN && type < EPOLL_EVENT_END)) {
        FI_HILOGE("Invalid type:%{public}d", type);
        return RET_ERR;
    }
    if (fd < 0) {
        FI_HILOGE("Invalid fd:%{public}d", fd);
        return RET_ERR;
    }
    auto eventData = static_cast<device_status_epoll_event*>(malloc(sizeof(device_status_epoll_event)));
    if (!eventData) {
        FI_HILOGE("Malloc failed");
        return RET_ERR;
    }
    eventData->fd = fd;
    eventData->event_type = type;
    FI_HILOGD("EventData:[fd:%{public}d, type:%{public}d]", eventData->fd, eventData->event_type);

    struct epoll_event ev {};
    ev.events = EPOLLIN;
    ev.data.ptr = eventData;
    if (EpollCtl(fd, EPOLL_CTL_ADD, ev) != RET_OK) {
        free(eventData);
        eventData = nullptr;
        ev.data.ptr = nullptr;
        FI_HILOGE("EpollCtl failed");
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ContextService::DelEpoll(EpollEventType type, int32_t fd)
{
    CALL_DEBUG_ENTER;
    if (!(type >= EPOLL_EVENT_BEGIN && type < EPOLL_EVENT_END)) {
        FI_HILOGE("Invalid type:%{public}d", type);
        return RET_ERR;
    }
    if (fd < 0) {
        FI_HILOGE("Invalid fd:%{public}d", fd);
        return RET_ERR;
    }
    struct epoll_event ev {};
    if (EpollCtl(fd, EPOLL_CTL_DEL, ev) != RET_OK) {
        FI_HILOGE("DelEpoll failed");
        return RET_ERR;
    }
    return RET_OK;
}

void ContextService::EpollClose()
{
    CALL_DEBUG_ENTER;
    if (epollFd_ >= 0) {
        if (close(epollFd_) < 0) {
            FI_HILOGE("Close epoll fd failed, error:%{public}s, epollFd_:%{public}d", strerror(errno), epollFd_);
        }
        epollFd_ = -1;
    }
}

int32_t ContextService::EpollCtl(int32_t fd, int32_t op, struct epoll_event &event)
{
    CALL_DEBUG_ENTER;
    if (fd < 0) {
        FI_HILOGE("Invalid fd:%{public}d", fd);
        return RET_ERR;
    }
    if (epollFd_ < 0) {
        FI_HILOGE("Invalid epollFd:%{public}d", epollFd_);
        return RET_ERR;
    }
    if (::epoll_ctl(epollFd_, op, fd, &event) != 0) {
        FI_HILOGE("epoll_ctl(%{public}d,%{public}d,%{public}d) failed:%{public}s", epollFd_, op, fd, ::strerror(errno));
        return RET_ERR;
    }
    return RET_OK;
}

int32_t ContextService::EpollWait(int32_t maxevents, int32_t timeout, struct epoll_event &events)
{
    if (epollFd_ < 0) {
        FI_HILOGE("Invalid epollFd:%{public}d", epollFd_);
        return RET_ERR;
    }
    return epoll_wait(epollFd_, &events, maxevents, timeout);
}

void ContextService::OnTimeout(const struct epoll_event &ev)
{
    CALL_DEBUG_ENTER;
    if ((ev.events & EPOLLIN) == EPOLLIN) {
        uint64_t expiration {};
        ssize_t ret = read(timerMgr_.GetTimerFd(), &expiration, sizeof(expiration));
        if (ret < 0) {
            FI_HILOGE("Read expiration failed:%{public}s", strerror(errno));
        }
        timerMgr_.ProcessTimers();
    } else if ((ev.events & (EPOLLHUP | EPOLLERR)) != 0) {
        FI_HILOGE("Epoll hangup:%{public}s", strerror(errno));
    }
}

void ContextService::OnDeviceMgr(const struct epoll_event &ev)
{
    CALL_DEBUG_ENTER;
    if ((ev.events & EPOLLIN) == EPOLLIN) {
        devMgr_.Dispatch(ev);
    } else if ((ev.events & (EPOLLHUP | EPOLLERR)) != 0) {
        FI_HILOGE("Epoll hangup:%{public}s", strerror(errno));
    }
}

int32_t ContextService::EnableDevMgr(int32_t nRetries)
{
    CALL_INFO_TRACE;
    static int32_t timerId { -1 };
    int32_t ret = devMgr_.Enable();
    if (ret != RET_OK) {
        FI_HILOGE("Failed to enable device manager");
        if (nRetries > 0) {
            timerId = timerMgr_.AddTimer(DEFAULT_WAIT_TIME_MS, WAIT_FOR_ONCE,
                [this, nRetries] { return this->EnableDevMgr(nRetries - 1); });
            if (timerId < 0) {
                FI_HILOGE("AddTimer failed, Failed to enable device manager");
            }
        } else {
            FI_HILOGE("Maximum number of retries exceeded, Failed to enable device manager");
        }
        return ret;
    }
    AddEpoll(EPOLL_EVENT_DEVICE_MGR, devMgr_.GetFd());
    if (timerId >= 0) {
        timerMgr_.RemoveTimer(timerId);
        timerId = -1;
    }
    return RET_OK;
}

void ContextService::DisableDevMgr()
{
    DelEpoll(EPOLL_EVENT_DEVICE_MGR, devMgr_.GetFd());
    devMgr_.Disable();
}

void ContextService::OnStart()
{
    CALL_DEBUG_ENTER;
    uint64_t tid = GetThisThreadId();
    delegateTasks_.SetWorkerThreadId(tid);

    if (!Init()) {
        FI_HILOGE("On start call init failed");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    ready_ = true;

    worker_ = std::thread(std::bind(&ContextService::OnThread, this));
}

void ContextService::OnStop()
{
    CALL_DEBUG_ENTER;
    if (timerMgr_.GetTimerFd() >= 0) {
        if (close(timerMgr_.GetTimerFd()) < 0) {
            FI_HILOGE("Close timer fd failed, error:%{public}s", strerror(errno));
        }
    }
    if (!ready_) {
        FI_HILOGI("ready state is false");
        return;
    }
    ready_ = false;
    state_ = ServiceRunningState::STATE_EXIT;

    delegateTasks_.PostAsyncTask([]() -> int32_t {
        FI_HILOGD("No asynchronous operations");
        return RET_OK;
    });
    if (worker_.joinable()) {
        worker_.join();
    }
    DisableDevMgr();
    EpollClose();
    FI_HILOGI("OnStop leave");
}

void ContextService::OnThread()
{
    CALL_DEBUG_ENTER;
    SetThreadName(std::string("os_ds_service"));
    uint64_t tid = GetThisThreadId();
    delegateTasks_.SetWorkerThreadId(tid);
    EnableDevMgr(MAX_N_RETRIES);
    FI_HILOGD("Main worker thread start, tid:%{public}" PRId64 "", tid);

    while (state_ == ServiceRunningState::STATE_RUNNING) {
        struct epoll_event ev[MAX_EVENT_SIZE] {};
        int32_t count = EpollWait(MAX_EVENT_SIZE, -1, ev[0]);
        for (int32_t i = 0; i < count && state_ == ServiceRunningState::STATE_RUNNING; i++) {
            auto epollEvent = reinterpret_cast<device_status_epoll_event*>(ev[i].data.ptr);
            CHKPC(epollEvent);
            if (epollEvent->event_type == EPOLL_EVENT_TIMER) {
                OnTimeout(ev[i]);
            } else if (epollEvent->event_type == EPOLL_EVENT_ETASK) {
                OnDelegateTask(ev[i]);
            } else if (epollEvent->event_type == EPOLL_EVENT_DEVICE_MGR) {
                OnDeviceMgr(ev[i]);
            } else {
                FI_HILOGW("Unknown epoll event type:%{public}d", epollEvent->event_type);
            }
        }
    }
    FI_HILOGD("Main worker thread stop, tid:%{public}" PRId64 "", tid);
}

void ContextService::OnDelegateTask(const struct epoll_event &ev)
{
    if ((ev.events & EPOLLIN) == 0) {
        FI_HILOGW("Not epollin");
        return;
    }
    DelegateTasks::TaskData data {};
    ssize_t res = read(delegateTasks_.GetReadFd(), &data, sizeof(data));
    if (res == -1) {
        FI_HILOGW("Read failed erron:%{public}d", errno);
    }
    FI_HILOGD("RemoteRequest notify td:%{public}" PRId64 ", std:%{public}" PRId64 ""
        ", taskId:%{public}d", GetThisThreadId(), data.tid, data.taskId);
    delegateTasks_.ProcessTasks();
}

void IntentionDeviceManagerTest::SetUpTestCase() {}

void IntentionDeviceManagerTest::TearDownTestCase()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP_MS));
}

void IntentionDeviceManagerTest::SetUp() {}

void IntentionDeviceManagerTest::TearDown() {}

/**
 * @tc.name: IntentionDeviceManagerTest01
 * @tc.desc: Test the founction AddDevice
 * @tc.type: FUNC
 */
HWTEST_F(IntentionDeviceManagerTest, IntentionDeviceManagerTest01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    env->devMgr_.RemoveDevice(TEST_DEV_NODE);
    env->devMgr_.FindDevice(TEST_DEV_NODE);
    auto ret = env->devMgr_.AddDevice(TEST_DEV_NODE);
    ASSERT_EQ(ret, nullptr);
    ret = env->devMgr_.FindDevice(TEST_DEV_NODE);
    ASSERT_EQ(ret, nullptr);
    ret = env->devMgr_.RemoveDevice(TEST_DEV_NODE);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: IntentionDeviceManagerTest02
 * @tc.desc: Test the founction Dispatch
 * @tc.type: FUNC
 */
HWTEST_F(IntentionDeviceManagerTest, IntentionDeviceManagerTest02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    auto eventData = static_cast<device_status_epoll_event*>(malloc(sizeof(device_status_epoll_event)));
    eventData->fd = 1;
    eventData->event_type = EPOLL_EVENT_BEGIN;
    struct epoll_event ev {};
    ev.events = EPOLLIN;
    ev.data.ptr = eventData;
    ASSERT_NO_FATAL_FAILURE(env->devMgr_.Dispatch(ev));
}

/**
 * @tc.name: IntentionDeviceManagerTest03
 * @tc.desc: Test the founction GetDevice
 * @tc.type: FUNC
 */
HWTEST_F(IntentionDeviceManagerTest, IntentionDeviceManagerTest03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    auto ret = env->GetDeviceManager().GetDevice(1);
    ASSERT_EQ(ret, nullptr);
}


/**
 * @tc.name: IntentionDeviceManagerTest04
 * @tc.desc: Test the founction RetriggerHotplug
 * @tc.type: FUNC
 */
HWTEST_F(IntentionDeviceManagerTest, IntentionDeviceManagerTest04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    std::weak_ptr<IDeviceObserver> weakObserver = std::weak_ptr<IDeviceObserver>();
    ASSERT_NO_FATAL_FAILURE(env->GetDeviceManager().RetriggerHotplug(weakObserver));
}

/**
 * @tc.name: IntentionDeviceManagerTest05
 * @tc.desc: Test the founction AddDeviceObserver
 * @tc.type: FUNC
 */
HWTEST_F(IntentionDeviceManagerTest, IntentionDeviceManagerTest05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    std::weak_ptr<IDeviceObserver> weakObserver = std::weak_ptr<IDeviceObserver>();
    int32_t ret = env->GetDeviceManager().AddDeviceObserver(weakObserver);
    EXPECT_EQ(ret, RET_ERR);
    ASSERT_NO_FATAL_FAILURE(env->GetDeviceManager().RemoveDeviceObserver(weakObserver));
}

/**
 * @tc.name: IntentionDeviceManagerTest06
 * @tc.desc: Test the founction GetKeyboard
 * @tc.type: FUNC
 */
HWTEST_F(IntentionDeviceManagerTest, IntentionDeviceManagerTest06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto env = ContextService::GetInstance();
    ASSERT_NE(env, nullptr);
    env->devMgr_.AddDevice(TEST_DEV_NODE);
    std::vector<std::shared_ptr<IDevice>> keyboards;
    keyboards = env->devMgr_.GetKeyboard();
    bool ret = env->devMgr_.HasKeyboard();
    ASSERT_FALSE(ret);
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS