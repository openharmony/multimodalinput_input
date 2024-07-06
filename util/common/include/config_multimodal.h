/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONFIG_MULTIMODAL_H
#define CONFIG_MULTIMODAL_H

namespace OHOS {
namespace MMI {
#define DEF_MMI_EVENT_INJECTION "/system/bin/mmi-event-injection"
#define DEF_MMI_VIRTUAL_DEVICE_MANAGER "/system/bin/mmi-virtual-device-manager"
#define DEF_MMI_DATA_ROOT "/data/mmi/"
#define DEF_EXP_CONFIG "/system/etc/mmi_device_config.ini"
#ifdef __aarch64__
    #define DEF_EXP_SOPATH "/system/lib64/"
#else
    #define DEF_EXP_SOPATH "/system/lib/"
#endif
#define DEF_SCREEN_MAX_WIDTH 480
#define DEF_SCREEN_MAX_HEIGHT 960

// Maximum buffer size of network packets
#define MAX_PACKET_BUF_SIZE (1024*8)
// Maximum buffer size of socket stream
#define MAX_STREAM_BUF_SIZE (MAX_PACKET_BUF_SIZE*2)
#define MAX_VECTOR_SIZE 1000
#define MAX_INPUT_DEVICE 64
#define MAX_SUPPORT_KEY 5
#define MAX_KEY_SIZE 395

// Instantaneous maximum listening buffer size of socket
#define MAX_LIST_SIZE 100
// Client quantity warning value
#define MAX_SESSON_ALARM 300
// Epoll create maximum event size
#define MAX_EVENT_SIZE 100
// Default epoll write timeout
#define DEFINE_EPOLL_TIMEOUT 1000
// Client reconnection cooldown
#define CLIENT_RECONNECT_COOLING_TIME 800
// Server failure restart cooldown
#define SERVER_RESTART_COOLING_TIME 2000
// Thread death threshold time
#define MAX_THREAD_DEATH_TIME (6*1000)
// notifyDeviceChange@Device added
#define MMISEVER_WMS_DEVICE_ADDED 1
// notifyDeviceChange@Device removed
#define MMISEVER_WMS_DEVICE_REMOVE 2
#define SEND_RETRY_LIMIT 50
#define SEND_RETRY_SLEEP_TIME 500
#define ONCE_PROCESS_NETPACKET_LIMIT 100
#define MAX_RECV_LIMIT 32
#define INPUT_POINTER_DEVICES "input.pointer.device"
#define SUPER_PRIVACY_SWITCH "persist.input.switch"
#define MMI_DINPUT_PKG_NAME "ohos.multimodalinput.dinput"
} // namespace MMI
} // namespace OHOS
#endif // CONFIG_MULTIMODAL_H
