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

#ifndef I_DDM_ADAPTER_H
#define I_DDM_ADAPTER_H

#include <memory>
#include <string>

#include "dm_device_info.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class IBoardObserver {
public:
    IBoardObserver() = default;
    virtual ~IBoardObserver() = default;

    virtual void OnBoardOnline(const std::string &networkId) = 0;
    virtual void OnBoardOffline(const std::string &networkId) = 0;
};

class IDDMAdapter {
public:
    IDDMAdapter() = default;
    virtual ~IDDMAdapter() = default;

    virtual int32_t Enable() = 0;
    virtual void Disable() = 0;
    virtual void AddBoardObserver(std::shared_ptr<IBoardObserver> observer) = 0;
    virtual void RemoveBoardObserver(std::shared_ptr<IBoardObserver> observer) = 0;
    virtual bool CheckSameAccountToLocal(const std::string &networkId) = 0;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // I_DDM_ADAPTER_H
