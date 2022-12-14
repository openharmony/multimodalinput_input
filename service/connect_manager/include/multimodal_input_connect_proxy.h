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
    ~MultimodalInputConnectProxy() override = default;
    int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType,
        int32_t &socketFd, int32_t &tokenType) override;
    int32_t AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority) override;
    int32_t RemoveInputEventFilter(int32_t filterId) override;
    int32_t SetPointerVisible(bool visible) override;
    int32_t IsPointerVisible(bool &visible) override;
    int32_t MarkProcessed(int32_t eventType, int32_t eventId) override;
    int32_t SetPointerSpeed(int32_t speed) override;
    int32_t GetPointerSpeed(int32_t &speed) override;
    int32_t SetPointerStyle(int32_t windowId, int32_t pointerStyle) override;
    int32_t GetPointerStyle(int32_t windowId, int32_t &pointerStyle) override;
    int32_t SupportKeys(int32_t deviceId, std::vector<int32_t> &keys, std::vector<bool> &keystroke) override;
    int32_t GetDeviceIds(std::vector<int32_t> &ids) override;
    int32_t GetDevice(int32_t deviceId, std::shared_ptr<InputDevice> &inputDevice) override;
    int32_t RegisterDevListener() override;
    int32_t UnregisterDevListener() override;
    int32_t GetKeyboardType(int32_t deviceId, int32_t &keyboardType) override;
    int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags) override;
    int32_t RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags) override;
    int32_t MarkEventConsumed(int32_t eventId) override;
    int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY) override;
    int32_t InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
    int32_t SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option) override;
    int32_t UnsubscribeKeyEvent(int32_t subscribeId) override;
    int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
    int32_t SetAnrObserver() override;
    int32_t RegisterCooperateListener() override;
    int32_t UnregisterCooperateListener() override;
    int32_t EnableInputDeviceCooperate(int32_t userData, bool enabled) override;
    int32_t StartInputDeviceCooperate(int32_t userData, const std::string &sinkDeviceId,
        int32_t srcInputDeviceId) override;
    int32_t StopDeviceCooperate(int32_t userData) override;
    int32_t GetInputDeviceCooperateState(int32_t userData, const std::string &deviceId) override;
    int32_t SetInputDevice(const std::string& dhid, const std::string& screenId) override;
    int32_t GetFunctionKeyState(int32_t funcKey, bool &state) override;
    int32_t SetFunctionKeyState(int32_t funcKey, bool enable) override;
    int32_t SetPointerLocation(int32_t x, int32_t y) override;
    virtual int32_t SetMouseCaptureMode(int32_t windowId, bool isCaptureMode) override;

private:
    static inline BrokerDelegator<MultimodalInputConnectProxy> delegator_;
};
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_CONNECT_PROXY_H
