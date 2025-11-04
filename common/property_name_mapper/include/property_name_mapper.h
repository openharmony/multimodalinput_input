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

#ifndef PROPERTY_NAME_MAPPER_H
#define PROPERTY_NAME_MAPPER_H

#include <memory>
#include <shared_mutex>

#include "nocopyable.h"

#include "component_manager.h"
#include "i_property_name_mapper.h"

namespace OHOS {
namespace MMI {
class PropertyNameMapper final : public IPropertyNameMapper {
public:
    enum class UnloadOption {
        UNLOAD_MANUALLY = 0,
        UNLOAD_AUTOMATICALLY,
        UNLOAD_AUTOMATICALLY_WITH_DELAY,
    };

    static std::shared_ptr<PropertyNameMapper> Load(UnloadOption option);
    static void Unload(UnloadOption option);

    PropertyNameMapper() = default;
    ~PropertyNameMapper() = default;
    DISALLOW_COPY_AND_MOVE(PropertyNameMapper);

    int32_t MapKey(const std::string &name) const override;
    PointerEvent::AxisType MapAxis(const std::string &name) const override;

private:
    void LoadPropertyNameMap();

    static std::shared_mutex mutex_;
    static std::shared_ptr<PropertyNameMapper> instance_;
    static int32_t timerId_;
    std::unique_ptr<IPropertyNameMapper, ComponentManager::Component<IPropertyNameMapper>> mapper_ {
        nullptr, ComponentManager::Component<IPropertyNameMapper>(nullptr, nullptr) };
};
} // namespace MMI
} // namespace OHOS
#endif // PROPERTY_NAME_MAPPER_H
