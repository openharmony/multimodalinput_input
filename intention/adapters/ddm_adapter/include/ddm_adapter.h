/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DDM_ADAPTER_H
#define DDM_ADAPTER_H

#include "nocopyable.h"

#include "i_ddm_adapter.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DDMAdapter final : public IDDMAdapter {
public:
    DDMAdapter();
    ~DDMAdapter() = default;
    DISALLOW_COPY_AND_MOVE(DDMAdapter);

    int32_t Enable() override;
    void Disable() override;

    void AddBoardObserver(std::shared_ptr<IBoardObserver> observer) override;
    void RemoveBoardObserver(std::shared_ptr<IBoardObserver> observer) override;
    bool CheckSameAccountToLocal(const std::string &networkId) override;

private:
    std::shared_ptr<IDDMAdapter> ddm_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DDM_ADAPTER_H
