/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef MULTIMODAL_INPUT_CONNECT_PROXY_H
#define MULTIMODAL_INPUT_CONNECT_PROXY_H

#include "iremote_object.h"
#include "iremote_proxy.h"
#include "nocopyable.h"
#include "system_ability.h"

#include "i_multimodal_input_connect.h"

namespace OHOS {
namespace MMI {
class MultimodalInputConnectProxy final : public IRemoteProxy<IMultimodalInputConnect> {
public:
    explicit MultimodalInputConnectProxy(const sptr<IRemoteObject> &impl);
    DISALLOW_COPY_AND_MOVE(MultimodalInputConnectProxy);
    virtual ~MultimodalInputConnectProxy() override;
    virtual int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType,
        int32_t &socketFd, int32_t &tokenType) override;
    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter) override;
    virtual int32_t SetPointerVisible(bool visible) override;
    virtual int32_t IsPointerVisible(bool &visible) override;
    virtual int32_t SetPointerSpeed(int32_t speed) override;
    virtual int32_t GetPointerSpeed(int32_t &speed) override;
    virtual int32_t SetPointerStyle(int32_t windowId, int32_t pointerStyle) override;
    virtual int32_t GetPointerStyle(int32_t windowId, int32_t &pointerStyle) override;
    virtual int32_t SupportKeys(int32_t userData, int32_t deviceId, std::vector<int32_t> &keys) override;
    virtual int32_t GetDeviceIds(int32_t userData) override;
    virtual int32_t GetDevice(int32_t userData, int32_t deviceId) override;
    virtual int32_t RegisterDevListener() override;
    virtual int32_t UnregisterDevListener() override;
    virtual int32_t GetKeyboardType(int32_t userData, int32_t deviceId) override;
    virtual int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType) override;
    virtual int32_t RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType) override;
    virtual int32_t MarkEventConsumed(int32_t eventId) override;
    virtual int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY) override;
    virtual int32_t InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
    virtual int32_t SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option) override;
    virtual int32_t UnsubscribeKeyEvent(int32_t subscribeId) override;
    virtual int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
    virtual int32_t SetAnrObserver() override;
    virtual int32_t RegisterCooperateListener() override;
    virtual int32_t UnregisterCooperateListener() override;
    virtual int32_t EnableInputDeviceCooperate(int32_t userData, bool enabled) override;
    virtual int32_t StartInputDeviceCooperate(int32_t userData, const std::string &sinkDeviceId,
        int32_t srcInputDeviceId) override;
    virtual int32_t StopDeviceCooperate(int32_t userData) override;
    virtual int32_t GetInputDeviceCooperateState(int32_t userData, const std::string &deviceId) override;
    virtual int32_t SetInputDevice(const std::string& dhid, const std::string& screenId) override;
    virtual int32_t GetFunctionKeyState(int32_t funcKey, bool &state) override;
    virtual int32_t SetFunctionKeyState(int32_t funcKey, bool enable) override;

private:
    static inline BrokerDelegator<MultimodalInputConnectProxy> delegator_;
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_CONNECT_PROXY_H
