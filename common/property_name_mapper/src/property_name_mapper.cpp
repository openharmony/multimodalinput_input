/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "property_name_mapper.h"

#include "component_manager.h"
#include "key_event.h"
#include "timer_manager.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_SERVER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PropertyNameMapper"

namespace OHOS {
namespace MMI {
namespace {
constexpr char LIB_PROPERTY_NAME_MAPPER_NAME[] { "libmmi_property_name_mapper.z.so" };
constexpr int32_t DEFAULT_UNLOAD_DELAY_TIME { 30000 };
constexpr int32_t REPEAT_ONCE { 1 };
}

std::shared_mutex PropertyNameMapper::mutex_ {};
std::shared_ptr<PropertyNameMapper> PropertyNameMapper::instance_ { nullptr };
int32_t PropertyNameMapper::timerId_ { -1 };

std::shared_ptr<PropertyNameMapper> PropertyNameMapper::Load(UnloadOption option)
{
    std::unique_lock guard { mutex_ };
    TimerMgr->RemoveTimer(timerId_);
    timerId_ = -1;

    if (instance_ == nullptr) {
        instance_ = std::make_shared<PropertyNameMapper>();
        if (instance_ == nullptr) {
            MMI_HILOGE("Failed to load PropertyNameMapper");
            return nullptr;
        }
        instance_->LoadPropertyNameMap();
    }
    if (option == UnloadOption::UNLOAD_AUTOMATICALLY) {
        auto propertyNameMapper = instance_;
        instance_ = nullptr;
        return propertyNameMapper;
    }
    if (option != UnloadOption::UNLOAD_AUTOMATICALLY_WITH_DELAY) {
        return instance_;
    }

    timerId_ = TimerMgr->AddTimer(
        DEFAULT_UNLOAD_DELAY_TIME, REPEAT_ONCE,
        []() {
            PropertyNameMapper::Unload(UnloadOption::UNLOAD_AUTOMATICALLY);
        });
    return instance_;
}

void PropertyNameMapper::Unload(UnloadOption option)
{
    std::unique_lock guard { mutex_ };
    if (instance_ == nullptr) {
        return;
    }
    TimerMgr->RemoveTimer(timerId_);
    timerId_ = -1;

    if (option != UnloadOption::UNLOAD_AUTOMATICALLY_WITH_DELAY) {
        instance_ = nullptr;
        return;
    }
    timerId_ = TimerMgr->AddTimer(
        DEFAULT_UNLOAD_DELAY_TIME, REPEAT_ONCE,
        []() {
            PropertyNameMapper::Unload(UnloadOption::UNLOAD_AUTOMATICALLY);
        });
}

int32_t PropertyNameMapper::MapKey(const std::string &name) const
{
    CHKPR(mapper_, KeyEvent::KEYCODE_UNKNOWN);
    return mapper_->MapKey(name);
}

PointerEvent::AxisType PropertyNameMapper::MapAxis(const std::string &name) const
{
    CHKPR(mapper_, PointerEvent::AXIS_TYPE_UNKNOWN);
    return mapper_->MapAxis(name);
}

void PropertyNameMapper::LoadPropertyNameMap()
{
    mapper_ = ComponentManager::LoadLibrary<IPropertyNameMapper>(
        nullptr, LIB_PROPERTY_NAME_MAPPER_NAME);
}
} // namespace MMI
} // namespace OHOS
