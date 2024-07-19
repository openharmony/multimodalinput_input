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

#ifndef DDM_ADAPTER_IMPL_H
#define DDM_ADAPTER_IMPL_H

#include <mutex>
#include <set>

#include "device_manager.h"
#include "nocopyable.h"

#include "i_ddm_adapter.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
class DDMAdapterImpl final : public IDDMAdapter, public std::enable_shared_from_this<DDMAdapterImpl> {
public:
    DDMAdapterImpl() = default;
    ~DDMAdapterImpl();
    DISALLOW_COPY_AND_MOVE(DDMAdapterImpl);

    int32_t Enable() override;
    void Disable() override;

    void AddBoardObserver(std::shared_ptr<IBoardObserver> observer) override;
    void RemoveBoardObserver(std::shared_ptr<IBoardObserver> observer) override;
    bool CheckSameAccountToLocal(const std::string &networkId) override;

private:
    int32_t GetTrustedDeviceList(std::vector<DistributedHardware::DmDeviceInfo> &deviceList);

private:
    class Observer final {
    public:
        explicit Observer(std::shared_ptr<IBoardObserver> observer)
            : observer_(observer) {}

        Observer() = default;
        ~Observer() = default;
        DISALLOW_COPY_AND_MOVE(Observer);

        std::shared_ptr<IBoardObserver> Lock() const noexcept
        {
            return observer_.lock();
        }

        bool operator<(const Observer &other) const noexcept
        {
            return (observer_.lock() < other.observer_.lock());
        }

    private:
        std::weak_ptr<IBoardObserver> observer_;
    };

    class DmInitCb final : public DistributedHardware::DmInitCallback {
    public:
        DmInitCb() = default;
        ~DmInitCb() = default;
        DISALLOW_COPY_AND_MOVE(DmInitCb);

        void OnRemoteDied() override {}
    };

    class DmBoardStateCb final : public DistributedHardware::DeviceStateCallback {
    public:
        DmBoardStateCb(std::shared_ptr<DDMAdapterImpl> dm) : dm_(dm) {}
        ~DmBoardStateCb() = default;
        DISALLOW_COPY_AND_MOVE(DmBoardStateCb);

        void OnDeviceOnline(const DistributedHardware::DmDeviceInfo &deviceInfo) override
        {
            std::shared_ptr<DDMAdapterImpl> dm = dm_.lock();
            if (dm != nullptr) {
                dm->OnBoardOnline(deviceInfo.networkId);
            }
        }

        void OnDeviceOffline(const DistributedHardware::DmDeviceInfo &deviceInfo) override
        {
            std::shared_ptr<DDMAdapterImpl> dm = dm_.lock();
            if (dm != nullptr) {
                dm->OnBoardOffline(deviceInfo.networkId);
            }
        }

        void OnDeviceChanged(const DistributedHardware::DmDeviceInfo &deviceInfo) override {}
        void OnDeviceReady(const DistributedHardware::DmDeviceInfo &deviceInfo) override {}

    private:
        std::weak_ptr<DDMAdapterImpl> dm_;
    };

    void OnBoardOnline(const std::string &networkId);
    void OnBoardOffline(const std::string &networkId);

    std::mutex lock_;
    std::shared_ptr<DmInitCb> initCb_;
    std::shared_ptr<DmBoardStateCb> boardStateCb_;
    std::set<Observer> observers_;
};
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // DDM_ADAPTER_IMPL_H
