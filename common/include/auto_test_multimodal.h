/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_LIBMMI_AUTOTEST_H
#define OHOS_LIBMMI_AUTOTEST_H

#include "proto.h"

#define MAX_EVENTTYPE_NAME 32

enum JOYSTICK_AXIS {
    JOYSTICK_AXIS_THROTTLE = 0,
    JOYSTICK_AXIS_HAT0X,
    JOYSTICK_AXIS_HAT0Y,
    JOYSTICK_AXIS_X,
    JOYSTICK_AXIS_Y,
    JOYSTICK_AXIS_Z,
    JOYSTICK_AXIS_RX,
    JOYSTICK_AXIS_RY,
    JOYSTICK_AXIS_RZ,
    JOYSTICK_AXIS_END
};

struct AutoTestLibinputPkt {
    char eventType[MAX_EVENTTYPE_NAME];      // 驱动上报事件类型
    uint32_t keyCode;                        // 原始键值
    int32_t keyState;                        // 状态 按下1 抬起0
    double rawX;                             // 相对x坐标偏移量
    double rawY;                             // 相对y坐标偏移量
    double absoluteX;                        // 绝对x坐标
    double absoluteY;                        // 绝对y坐标
};

struct AutoTestStandardPkt {
    int32_t reRventType;                     // 标准化前映射类型
    int32_t curRventType;                    // 标准化后事件类型
    uint32_t keyCode;                        // 原始键值
    int32_t keyState;                        // 状态 按下1 抬起0
    double rawX;                             // 相对x坐标偏移量
    double rawY;                             // 相对y坐标偏移量
    double absoluteX;                        // 绝对x坐标
    double absoluteY;                        // 绝对y坐标
};

struct AutoTestManagePkt {
    int32_t sizeOfWindowList;                // 窗口管理查询到的窗口id列表大小
    int32_t focusId;                         // 焦点窗口id
    int32_t windowId;                        // 需要切换焦点的窗口id
    bool disSystem;                          // 分发系统服务
    bool disClient;                          // 分发应用
    bool disCamrea;                          // 分发相机应用
    int32_t sizeOfAppManager;                // 客户端通道信息列表大小
};

struct AutoTestCoordinate {
    double windowRawX;                       // 完整窗口的绝对坐标X
    double windowRawY;                       // 完整窗口的绝对坐标Y
    double focusWindowRawX;                  // 焦点窗口的绝对坐标X
    double focusWindowRawY;                  // 焦点窗口的绝对坐标Y
};

struct AutoTestKeyTypePkt {
    bool disSystem;                          // 分发系统服务
    bool disClient;                          // 分发应用
    bool disCamrea;                          // 分发相机应用
};

struct AutoTestDispatcherPkt {
    char eventType[MAX_EVENTTYPE_NAME];      // 上报事件类型, 如: eventkeyboard
    int32_t sourceType;                      // 事件类型
    uint32_t keyOfHos;                       // L3键值
    int32_t keyState;                        // 状态 按下1 抬起0
    double rawX;                             // 相对x坐标偏移量
    double rawY;                             // 相对y坐标偏移量
    MmiMessageId mixedKey;                        // 组合键值(注册函数的键值)
    int32_t socketFd;                        // 通道号
    int32_t windowId;                        // 窗口Id
    int32_t abilityId;                       // 应用Id
    double absoluteX;                        // 绝对x坐标
    double absoluteY;                        // 绝对y坐标
    uint16_t deviceType;                     // 设备类型
    uint32_t inputDeviceId;                  // 设备Id
    uint16_t sizeOfstandardValue;            // 轴事件容器的大小
    int32_t slot;                            // 手指
};

struct AutoTestClientPkt {
    char eventType[MAX_EVENTTYPE_NAME];      // 上报事件类型, 如: eventkeyboard
    uint32_t keyOfHos;                       // L3键值
    int32_t keyState;                        // 状态 按下1 抬起0
    double rawX;                             // 相对x坐标偏移量
    double rawY;                             // 相对x坐标偏移量
    char callBakeName[MAX_EVENTTYPE_NAME];   // 回调函数
    int32_t socketFd;                        // 通道号
    int32_t windowId;                        // 窗口Id
    int32_t abilityId;                       // 应用Id
    double absoluteX;                        // 绝对x坐标
    double absoluteY;                        // 绝对y坐标
    int32_t deviceType;                     // 设备类型
    uint32_t inputDeviceId;                  // 设备Id
    int32_t sourceType;                      // 事件类型
    int32_t slot;                            // 手指
};

struct AutoTestClientListPkt {
    int32_t socketFd;                        // 通道号
    int32_t windowId;                        // 窗口Id
    int32_t abilityId;                       // 应用Id
};

#endif
