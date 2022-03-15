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

#ifndef CONFIG_MULTIMODAL_H
#define CONFIG_MULTIMODAL_H

namespace OHOS {
namespace MMI {
#define DEF_SEAT_ID "seat0"         // Default libinput seat

#ifndef OHOS_BUILD
    #define DEF_MMI_EVENT_INJECTION "/root/projects/build/bin/mmi-event-injection"
    #define DEF_MMI_VIRTUAL_DEVICE_MANAGER "/root/projects/build/bin/mmi-virtual-device-manager"
    #define DEF_MMI_DATA_ROOT       "/root/projects/run_root/"
    #define DEF_EXP_CONFIG          "/root/projects/run_root/etc/mmi_device_config.ini" // Default device config file
    #define DEF_EXP_SOPATH          "/root/projects/run_root/lib"                 // Default device so path
    #define DEF_SCREEN_MAX_WIDTH    65535          // Default screen max width
    #define DEF_SCREEN_MAX_HEIGHT   65535          // Default screen max height
#else
    #define DEF_MMI_EVENT_INJECTION "/system/bin/mmi-event-injection"
    #define DEF_MMI_VIRTUAL_DEVICE_MANAGER "/system/bin/mmi-virtual-device-manager"
    #define DEF_MMI_DATA_ROOT "/data/mmi/"
    #define DEF_EXP_CONFIG "/system/etc/mmi_device_config.ini"
    #define DEF_EXP_SOPATH "/system/lib/"
    #define DEF_SCREEN_MAX_WIDTH 480
    #define DEF_SCREEN_MAX_HEIGHT 960
#endif

#define MAX_PACKET_BUF_SIZE (1024*8)                // Maximum buffer size of network packets
#define MAX_STREAM_BUF_SIZE (MAX_PACKET_BUF_SIZE*2) // Maximum buffer size of socket stream

#define MAX_LIST_SIZE 100                   // Instantaneous maximum listening buffer size of socket
#define MAX_SESSON_ALARM 300                // Client quantity warning value
#define MAX_EVENT_SIZE 100                  // Epoll create maximum event size
#define DEFINE_EPOLL_TIMEOUT 1000           // Default epoll write timeout
#define CLIENT_RECONNECT_COOLING_TIME 800   // Client reconnection cooldown
#define SERVER_RESTART_COOLING_TIME 2000    // Server failure restart cooldown
#define MAX_THREAD_DEATH_TIME (6*1000)      // Thread death threshold time
#define MMISEVER_WMS_DEVICE_ADDED 1         // notifyDeviceChange@Device added
#define MMISEVER_WMS_DEVICE_REMOVE 2        // notifyDeviceChange@Device removed
} // namespace MMI
} // namespace OHOS
#endif // CONFIG_MULTIMODAL_H