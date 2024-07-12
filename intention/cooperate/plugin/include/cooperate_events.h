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

#ifndef COOPERATE_EVENTS_H
#define COOPERATE_EVENTS_H

#include <future>
#include <string>
#include <variant>

#include "coordination_message.h"
#include "i_cooperate.h"
#include "i_device.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
enum CooperateState : size_t {
    COOPERATE_STATE_FREE = 0,
    COOPERATE_STATE_OUT,
    COOPERATE_STATE_IN,
    N_COOPERATE_STATES,
};

enum class CooperateEventType {
    NOOP,
    QUIT,
    ADD_OBSERVER,
    REMOVE_OBSERVER,
    REGISTER_LISTENER,
    UNREGISTER_LISTENER,
    REGISTER_HOTAREA_LISTENER,
    UNREGISTER_HOTAREA_LISTENER,
    ENABLE,
    DISABLE,
    START,
    STOP,
    GET_COOPERATE_STATE,
    REGISTER_EVENT_LISTENER,
    UNREGISTER_EVENT_LISTENER,
    DUMP,
    APP_CLOSED,
    DDM_BOARD_ONLINE,
    DDM_BOARD_OFFLINE,
    DDP_COOPERATE_SWITCH_CHANGED,
    INPUT_HOTPLUG_EVENT,
    INPUT_POINTER_EVENT,
    DSOFTBUS_SESSION_OPENED,
    DSOFTBUS_SESSION_CLOSED,
    DSOFTBUS_START_COOPERATE,
    DSOFTBUS_COME_BACK,
    DSOFTBUS_STOP_COOPERATE,
    DSOFTBUS_RELAY_COOPERATE,
    DSOFTBUS_RELAY_COOPERATE_FINISHED,
    DSOFTBUS_SUBSCRIBE_MOUSE_LOCATION,
    DSOFTBUS_UNSUBSCRIBE_MOUSE_LOCATION,
    DSOFTBUS_REPLY_SUBSCRIBE_MOUSE_LOCATION,
    DSOFTBUS_REPLY_UNSUBSCRIBE_MOUSE_LOCATION,
    DSOFTBUS_MOUSE_LOCATION,
    UPDATE_COOPERATE_FLAG,
    DSOFTBUS_INPUT_DEV_SYNC,
    DSOFTBUS_INPUT_DEV_HOT_PLUG,
};

struct Rectangle {
    int32_t width;
    int32_t height;
    int32_t x;
    int32_t y;
};

struct AddObserverEvent {
    std::shared_ptr<ICooperateObserver> observer;
};
using RemoveObserverEvent = AddObserverEvent;

struct RegisterListenerEvent {
    int32_t pid;
    int32_t userData;
};

using UnregisterListenerEvent = RegisterListenerEvent;
using RegisterHotareaListenerEvent = RegisterListenerEvent;
using UnregisterHotareaListenerEvent = RegisterListenerEvent;
using DisableCooperateEvent = RegisterListenerEvent;

struct StartCooperateEvent {
    int32_t pid;
    int32_t userData;
    std::string remoteNetworkId;
    int32_t startDeviceId;
    std::shared_ptr<std::promise<int32_t>> errCode;
};

struct EnableCooperateEvent {
    int32_t tokenId;
    int32_t pid;
    int32_t userData;
};

struct ClientDiedEvent {
    int32_t pid;
};

struct StopCooperateEvent {
    int32_t pid;
    int32_t userData;
    bool isUnchained;
};

struct GetCooperateStateEvent {
    int32_t pid;
    int32_t userData;
    std::string networkId;
};

struct RegisterEventListenerEvent {
    int32_t pid;
    std::string networkId;
};
using UnregisterEventListenerEvent = RegisterEventListenerEvent;

struct DumpEvent {
    int32_t fd;
};

struct DDMBoardOnlineEvent {
    std::string networkId;
    bool normal;
    int32_t errCode { static_cast<int32_t>(CoordinationErrCode::COORDINATION_OK) };
};

using DDMBoardOfflineEvent = DDMBoardOnlineEvent;
using DDPCooperateSwitchChanged = DDMBoardOnlineEvent;

enum class InputHotplugType {
    PLUG,
    UNPLUG,
};

struct InputHotplugEvent {
    int32_t deviceId;
    InputHotplugType type;
    bool isKeyboard { false };
};

struct InputPointerEvent {
    int32_t deviceId;
    int32_t pointerAction;
    int32_t sourceType;
    Coordinate position;
};

using DSoftbusSessionOpened = DDMBoardOnlineEvent;
using DSoftbusSessionClosed = DDMBoardOnlineEvent;

struct DSoftbusStartCooperate {
    std::string networkId;
    std::string originNetworkId;
    bool success;
    NormalizedCoordinate cursorPos;
    StartCooperateData extra;
    int32_t errCode { static_cast<int32_t>(CoordinationErrCode::COORDINATION_OK) };
};

using DSoftbusStartCooperateFinished = DSoftbusStartCooperate;
using DSoftbusComeBack = DSoftbusStartCooperate;
using DSoftbusStopCooperate = DDMBoardOnlineEvent;
using DSoftbusStopCooperateFinished = DDMBoardOnlineEvent;

struct DSoftbusRelayCooperate {
    std::string networkId;
    std::string targetNetworkId;
    bool normal;
};

struct DSoftbusSubscribeMouseLocation {
    std::string networkId;
    std::string remoteNetworkId;
};

struct DSoftbusReplySubscribeMouseLocation {
    std::string networkId;
    std::string remoteNetworkId;
    bool result { false };
};

struct LocationInfo {
    int32_t displayX;
    int32_t displayY;
    int32_t displayWidth;
    int32_t displayHeight;
};
struct DSoftbusSyncMouseLocation {
    std::string networkId;
    std::string remoteNetworkId;
    LocationInfo mouseLocation;
};

struct DSoftbusSyncInputDevice {
    std::string networkId;
    std::vector<std::shared_ptr<IDevice>> devices;
};

struct DSoftbusHotPlugEvent {
    std::string networkId;
    InputHotplugType type;
    std::shared_ptr<IDevice> device;
};

using DSoftbusReplyUnSubscribeMouseLocation = DSoftbusReplySubscribeMouseLocation;
using DSoftbusUnSubscribeMouseLocation = DSoftbusSubscribeMouseLocation;

using DSoftbusRelayCooperateFinished = DSoftbusRelayCooperate;

struct UpdateCooperateFlagEvent {
    uint32_t mask;
    uint32_t flag;
};

struct CooperateEvent {
    CooperateEvent() : type(CooperateEventType::QUIT) {}

    explicit CooperateEvent(CooperateEventType ty) : type(ty) {}

    template<typename Event>
    CooperateEvent(CooperateEventType ty, Event ev) : type(ty), event(ev) {}

    CooperateEventType type;
    std::variant<
        AddObserverEvent,
        RegisterListenerEvent,
        StartCooperateEvent,
        StopCooperateEvent,
        EnableCooperateEvent,
        GetCooperateStateEvent,
        RegisterEventListenerEvent,
        DSoftbusSubscribeMouseLocation,
        DSoftbusReplySubscribeMouseLocation,
        DSoftbusSyncMouseLocation,
        DumpEvent,
        DDMBoardOnlineEvent,
        InputHotplugEvent,
        InputPointerEvent,
        DSoftbusStartCooperate,
        DSoftbusRelayCooperate,
        ClientDiedEvent,
        UpdateCooperateFlagEvent,
        DSoftbusSyncInputDevice,
        DSoftbusHotPlugEvent
    > event;
};

inline constexpr int32_t DEFAULT_TIMEOUT { 3000 };
inline constexpr int32_t REPEAT_ONCE { 1 };
inline constexpr int32_t DEFAULT_COOLING_TIME { 10 };
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_EVENTS_H
