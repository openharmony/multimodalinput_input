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

#ifndef PROPERTY_NAME_MAPPER_IMPL_H
#define PROPERTY_NAME_MAPPER_IMPL_H

#include "nocopyable.h"

#include "i_property_name_mapper.h"

namespace OHOS {
namespace MMI {
class PropertyNameMapperImpl final : public IPropertyNameMapper {
public:
    PropertyNameMapperImpl() = default;
    ~PropertyNameMapperImpl() = default;
    DISALLOW_COPY_AND_MOVE(PropertyNameMapperImpl);

    int32_t MapKey(const std::string &name) const override;
    PointerEvent::AxisType MapAxis(const std::string &name) const override;
};
} // namespace MMI
} // namespace OHOS
#endif // PROPERTY_NAME_MAPPER_IMPL_H
