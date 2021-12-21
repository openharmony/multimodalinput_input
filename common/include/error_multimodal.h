/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_ERROR_MULTIMODAL_H
#define OHOS_ERROR_MULTIMODAL_H
#include <errors.h>

namespace OHOS {
    enum MmiModuleType {
        MODULE_CLIENT = 0x00,
        MODULE_EVENT_SIMULATE = 0x01,
        MODULE_SERVER = 0x02,
        MODULE_UTIL = 0x03,
        MODULE_VIRTUAL_DEVICE = 0x04,
        MODULE_NAPI = 0x05
    };
    // Error code for client
    constexpr ErrCode CLIENT_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_CLIENT);

    enum {
        MSG_HANDLER_INIT_FAIL = CLIENT_ERR_OFFSET,  // 消息处理初始化失败
        START_CLI_FAIL,                             // 客户端启动失败
        EVENT_CONSUM_FAIL,                          // 事件消费失败
        UNKNOW_TOUCH_TYPE,                          // 客户端处理Touch时间时，收到了客户端发来的位置类型
        STRCPY_S_CALLBACK_FAIL,                     // strcpy_s返回错误
    };

    // Error code for event simulate
    constexpr ErrCode EVENT_SIMULATE_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_EVENT_SIMULATE);

    enum {
        FILE_OPEN_FAIL = EVENT_SIMULATE_ERR_OFFSET, // 文件打开失败
        STREAM_BUF_READ_FAIL,                       // 流缓冲读取失败
        EVENT_REG_FAIL,                             // 事件注册失败
        PARAM_INPUT_FAIL,                           // 注入携带参数错误
        EVENT_DATA_LEN_INPUT_FAIL,                  // 注入事件的数据长度错误
        TOUCH_CMD_INPUT_FAIL,                       // 注入的touch命令无效
        STRSET_SEC_FUN_FAIL,                        // strset安全函数错误
        DRIVE_PATH_INVALID,                         // 无效的驱动列表文件路径
        CMD_PATH_INVALID,                           // 无效的指令集文件路径
        CMD_STR_INVALID,                            // 无效指令字符串
    };
    // Error code for server
    constexpr ErrCode SERVER_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_SERVER);

    enum {
        MSG_SEND_FAIL = SERVER_ERR_OFFSET,          // 发送消息失败
        UNKNOWN_EVENT,                              // 未知的事件
        NULL_POINTER,                               // 空指针
        WINDOWS_MSG_INIT_FAIL,                      // 窗口管理器初始化失败
        APP_REG_INIT_FAIL,                          // APPRegister初始化失败
        SVR_MSG_HANDLER_INIT_FAIL,                  // 服务消息处理初始化失败
        INPUT_EVENT_HANDLER_INIT_FAIL,              // 输入事件处理初始化失败
        LIBINPUT_INIT_FAIL,                         // libinput初始化失败
        LIBINPUT_START_FAIL,                        // libinput启动失败
        LIBMMI_SVR_START_FAIL,                      // 多模服务启动失败
        LOG_CONFIG_FAIL,                            // log4z配置失败
        LOG_START_FAIL,                             // log4z启动失败
        PARAM_INPUT_INVALID,                        // 无效的输入参数
        INVALID_PARAM,                              // 无效的参数
        SENIOR_INPUT_DEV_INIT_FAIL,                 // 高级输入设备初始化失败
        LIBINPUT_DEV_EMPTY,                         // libinput设备为空
        REG_EVENT_DISP_FAIL,                        // 注册事件派发失败
        KEY_EVENT_DISP_FAIL,                        // 键盘事件派发失败
        INVAILD_COORDINATE,                         // 无效的坐标（坐标落点未找到窗口）
        ILLEGAL_DEV_ID,                             // 非法的设备fd
        DEV_REG_FAIL,                               // 设备注册失败
        FD_FIND_FAIL,                               // 查找fd失败
        CONN_BREAK,                                 // 连接断开
        SOCKET_BUF_FULL,                            // socket 缓冲区满
        WAITING_QUEUE_FULL,                         // 等待队列满
        APP_NOT_RESP,                               // ANR
        MEMCPY_SEC_FUN_FAIL,                        // memcpy安全函数错误
        LIBINPUT_DEV_NULLPTR,                       // libinput Device为空
        TOUCH_ID_NO_FIND,                           // 未找到touchid
        JOYSTICK_EVENT_DISP_FAIL,                   // 摇杆或手柄事件派发失败
        TOUCH_EVENT_DISP_FAIL,                      // 触摸屏事件派发失败
        POINT_REG_EVENT_DISP_FAIL,                  // 鼠标注册事件派发失败
        POINT_EVENT_DISP_FAIL,                      // 鼠标事件派发失败
        XKB_ALLOC_CONTEXT_FAIL,                     // XKB分配上下文失败
        XKB_INCL_PATH_FAIL,                         // XKB包含路径失败
        XKB_COMPILE_KEYMAP_FAIL,                    // XKB编译keymap失败
        XKB_ALLOC_STATE_FAIL,                       // XKB分配state失败
        KEY_EVENT_PKG_FAIL,                         // 键盘事件封装失败
        POINT_EVENT_PKG_FAIL,                       // 鼠标事件封装失败
        JOYSTICK_AXIS_EVENT_PKG_FAIL,               // 摇杆手柄轴事件封装失败
        JOYSTICK_KEY_EVENT_PKG_FAIL,                // 摇杆手柄键事件封装失败
        SPRINTF_S_SEC_FUN_FAIL,                     // sprintf_s安全函数错误
        SPCL_REG_EVENT_DISP_FAIL,                   // 特殊注册事件派发失败.
        TABLETPAD_KEY_EVENT_PKG_FAIL,               // 触控板键事件封装失败
        TABLETPAD_KEY_EVENT_DISP_FAIL,              // 触控板键事件派发失败
        TABLETPAD_EVENT_PKG_FAIL,                   // 触控板轴事件封装失败
        TABLETPAD_EVENT_DISP_FAIL,                  // 触控板轴事件派发失败
        TABLETTOOL_EVENT_PKG_FAIL,                  // 触控笔事件封装失败
        TABLETTOOL_EVENT_DISP_FAIL,                 // 触控笔事件派发失败
        MULTIDEVICE_SAME_EVENT_FAIL,                // 多设备相同事件返回标志
        GESTURE_EVENT_PKG_FAIL,                     // GESTURE_SWIPE事件封装失败
        STAT_CALL_FAIL,                             // stat函数调用失败
        REG_EVENT_PKG_FAIL,                         // 注册事件封装失败
        GESTURE_EVENT_DISP_FAIL,                    // gesture swipe事件派发失败
        DEV_PARAM_PKG_FAIL,                         // 设备号参数封装失败
        DEV_ADD_EVENT_PKG_FAIL,                     // 新增设备事件封装失败
        DEV_REMOVE_EVENT_PKG_FAIL,                  // 删除设备事件封装失败
        ADD_DEVICE_INFO_CALL_FAIL,                  // 调用AddDeviceInfo函数失败
        TOUCH_EVENT_PKG_FAIL,                       // 触摸屏事件封装失败
        UNKNOWN_EVENT_PKG_FAIL,                     // 未识别事件封装失败
        DEV_REG_INIT_FAIL,                          // DeviceRegister初始化失败
        MEMSET_SEC_FUN_FAIL,                        // memset安全函数错误
        DEVICEID_PARAM_PKG_FAIL,                    // 设备号参数封装失败
        MALLOC_FAIL,                                // malloc失败
        SEC_STRCPY_FAIL,                            // 安全函数strcpy错误
        SASERVICE_INIT_FAIL,                        // SA_Service初始化错误
        SASERVICE_START_FAIL,                       // SA_Service启动错误
        SASERVICE_STOP_FAIL,                        // SA_Service停止错误
        INVALID_RETURN_VALUE,                       // 无效的返回值
        EPOLL_CTL_FAIL,                             // epoll_ctl错误
        EXP_SO_LIBY_INIT_FAIL,                      // 可扩展模块初始化错误
    };
    // Error code for util
    constexpr ErrCode UTIL_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_UTIL);

    enum {
        NON_STD_EVENT = UTIL_ERR_OFFSET,            // 非标准化事件
        UNPROC_MSG,                                 // 未处理的消息
        UNKNOWN_MSG_ID,                             // 未知消息ID
        UNKNOWN_DEV,                                // 未知设备
        FILE_READ_FAIL,                             // 文件读取失败
        FILE_WRITE_FAIL,                            // 文件写入失败
        API_PARAM_TYPE_FAIL,                        // api参数类型错误
        API_OUT_OF_RANGE,                           // api返回值超出定义范围
        FOCUS_ID_OBTAIN_FAIL,                       // 获取focus_id失败
        SOCKET_PATH_INVALID,                        // 无效的Socket文件路径
        SOCKET_CREATE_FAIL,                         // Socket创建失败
        SOCKET_BIND_FAIL,                           // 监听Socket失败
        SOCKET_LISTEN_FAIL,                         // 监听Socket失败
        EPOLL_CREATE_FAIL,                          // EPOLL创建失败
        EPOLL_MODIFY_FAIL,                          // 修改EPOLL失败
        STREAM_BUF_WRITE_FAIL,                      // 流缓冲写入失败
        SESSION_ADD_FAIL,                           // 增加Session失败
        VAL_NOT_EXP,                                // 值不符合预期
        MEM_NOT_ENOUGH,                             // 没有足够的内存
        MEM_OUT_OF_BOUNDS,                          // 内存越界
        CONN_FAIL,                                  // 建立连接失败
        SESSION_NOT_FOUND,                          // 没有找到session
        FD_ACCEPT_FAIL,                             // 接受连接时fd无效
        PID_OBTAIN_FAIL,                            // 获取PID失败
        FD_OBTAIN_FAIL,                             // 获取FD失败
    };
    // Error code for virtual deviceparam
    constexpr ErrCode VIRTUAL_DEVICE_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_VIRTUAL_DEVICE);

    // Error code for napi
    constexpr ErrCode NAPI_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_NAPI);

    enum REGISTER {
        MMI_STANDARD_EVENT_SUCCESS = 1,
        MMI_STANDARD_EVENT_EXIST = 2,
        MMI_STANDARD_EVENT_INVALID_PARAMETER = -1,
        MMI_STANDARD_EVENT_NOT_EXIST = 3,
    };
    enum EXCEPTIONTEST {
        SERVICESELFCHECK = 1001,
        MULTIMODALINPUT_EXCEPTION_INJECTION = 1002,
    };

    enum MMI_SERVICE_STATUS {
        MMI_SERVICE_INVALID = 0, // 多模服务不存在，多模输入服务异常
        MMI_SERVICE_RUNNING,     // 多模服务运行正常
    };
}
#endif