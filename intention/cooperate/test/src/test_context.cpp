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

#include "test_context.h"

#include "dsoftbus_adapter.h"
#include "fi_log.h"
#include "plugin_manager.h"

#undef LOG_TAG
#define LOG_TAG "IntentionServiceTest"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {

int32_t MockDelegateTasks::PostSyncTask(DTaskCallback callback)
{
    return callback();
}

int32_t MockDelegateTasks::PostAsyncTask(DTaskCallback callback)
{
    return callback();
}

int32_t MockInputAdapter::AddMonitor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> callback)
{
    return RET_OK;
}

int32_t MockInputAdapter::AddMonitor(std::function<void(std::shared_ptr<MMI::KeyEvent>)> callback)
{
    return RET_OK;
}

void MockInputAdapter::RemoveMonitor(int32_t monitorId)
{}

int32_t MockInputAdapter::AddInterceptor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb)
{
    return RET_OK;
}

int32_t MockInputAdapter::AddInterceptor(std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb)
{
    return RET_OK;
}

int32_t MockInputAdapter::AddInterceptor(std::function<void(std::shared_ptr<MMI::PointerEvent>)> pointerCb,
    std::function<void(std::shared_ptr<MMI::KeyEvent>)> keyCb)
{
    return RET_OK;
}

void MockInputAdapter::RemoveInterceptor(int32_t interceptorId)
{}

int32_t MockInputAdapter::AddFilter(std::function<bool(std::shared_ptr<MMI::PointerEvent>)> callback)
{
    return RET_OK;
}

void MockInputAdapter::RemoveFilter(int32_t filterId)
{}

int32_t MockInputAdapter::SetPointerVisibility(bool visible, int32_t priority)
{
    return RET_OK;
}

int32_t MockInputAdapter::SetPointerLocation(int32_t x, int32_t y)
{
    return RET_OK;
}

int32_t MockInputAdapter::EnableInputDevice(bool enable)
{
    return RET_OK;
}

void MockInputAdapter::SimulateInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent)
{}

void MockInputAdapter::SimulateInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent)
{}

int32_t MockInputAdapter::AddVirtualInputDevice(std::shared_ptr<MMI::InputDevice> device, int32_t &deviceId)
{
    return RET_OK;
}

int32_t MockInputAdapter::RemoveVirtualInputDevice(int32_t deviceId)
{
    return RET_OK;
}

MockPluginManager::MockPluginManager(IContext *context)
{
    pluginMgr_ = std::make_unique<PluginManager>(context);
}

ICooperate* MockPluginManager::LoadCooperate()
{
    return pluginMgr_->LoadCooperate();
}

void MockPluginManager::UnloadCooperate()
{
    pluginMgr_->UnloadCooperate();
}

IMotionDrag* MockPluginManager::LoadMotionDrag()
{
    return nullptr;
}

void MockPluginManager::UnloadMotionDrag()
{}

TestContext::TestContext()
{
    input_ = std::make_unique<MockInputAdapter>();
    pluginMgr_ = std::make_unique<MockPluginManager>(this);
    dsoftbus_ = std::make_unique<DSoftbusAdapter>();
}

IDelegateTasks& TestContext::GetDelegateTasks()
{
    return delegateTasks_;
}

IDeviceManager& TestContext::GetDeviceManager()
{
    return devMgr_;
}

ITimerManager& TestContext::GetTimerManager()
{
    return timerMgr_;
}

IDragManager& TestContext::GetDragManager()
{
    return dragMgr_;
}

ISocketSessionManager& TestContext::GetSocketSessionManager()
{
    return socketSessionMgr_;
}

IPluginManager& TestContext::GetPluginManager()
{
    return *pluginMgr_;
}

IInputAdapter& TestContext::GetInput()
{
    return *input_;
}

IDSoftbusAdapter& TestContext::GetDSoftbus()
{
    return *dsoftbus_;
}
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
