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

#ifndef ERROR_MULTIMODAL_H
#define ERROR_MULTIMODAL_H

#include <errors.h>

namespace OHOS {
namespace MMI {
inline constexpr int32_t ERROR_UNSUPPORT = -2;
inline constexpr int32_t ARGV_VALID = 2;
inline constexpr int32_t ERROR_NO_PERMISSION = -201;

enum MmiModuleType {
    MODULE_CLIENT = 0x00,
    MODULE_EVENT_SIMULATE = 0x01,
    MODULE_SERVER = 0x02,
    MODULE_UTIL = 0x03
};
// Error code for client
constexpr ErrCode CLIENT_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_CLIENT);

enum {
    EVENT_CONSUM_FAIL = CLIENT_ERR_OFFSET,     // 事件消费失败
    CHECK_PERMISSION_FAIL                      // APL鉴权失败
};
// Error code for event simulate
constexpr ErrCode EVENT_SIMULATE_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_EVENT_SIMULATE);

enum {
    FILE_OPEN_FAIL = EVENT_SIMULATE_ERR_OFFSET, // 文件打开失败
    STREAM_BUF_READ_FAIL,                       // 流缓冲读取失败
    EVENT_REG_FAIL,                             // 事件注册失败
    PARAM_INPUT_FAIL                            // 注入携带参数错误
};
// Error code for server
constexpr ErrCode SERVER_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_SERVER);

enum {
    MSG_SEND_FAIL = SERVER_ERR_OFFSET,          // 发送消息失败
    UNKNOWN_EVENT,                              // 未知的事件
    ERROR_NULL_POINTER,                         // 空指针
    WINDOWS_MSG_INIT_FAIL,                      // 窗口管理器初始化失败
    LIBINPUT_INIT_FAIL,                         // libinput初始化失败
    PARAM_INPUT_INVALID,                        // 无效的输入参数
    KEY_EVENT_DISP_FAIL,                        // 键盘事件派发失败
    MEMCPY_SEC_FUN_FAIL,                        // memcpy安全函数错误
    KEY_EVENT_PKG_FAIL,                         // 键盘事件封装失败
    SPRINTF_S_SEC_FUN_FAIL,                     // sprintf_s安全函数错误
    MULTIDEVICE_SAME_EVENT_MARK,                // 多设备相同事件返回标志
    GESTURE_EVENT_PKG_FAIL,                     // GESTURE_SWIPE事件封装失败
    GESTURE_EVENT_DISP_FAIL,                    // gesture swipe事件派发失败
    SASERVICE_INIT_FAIL,                        // SA_Service初始化错误
    SASERVICE_PERMISSION_FAIL,                  // SA_Service权限不足
    ADD_SESSION_FAIL,                           // 增加session错误
    MAKE_SHARED_FAIL,                           // make_shared错误
    FCNTL_FAIL,                                 // fcntl 函数调用错误
    PACKET_WRITE_FAIL,                          // 写入数据错误
    PACKET_READ_FAIL,                           // 读取数据错误
    POINTER_DRAW_INIT_FAIL,                     // 初始化画鼠标失败
    MMISERVICE_NOT_RUNNING,                     // 多模服务未启动
    ETASKS_INIT_FAIL,                           // 代理任务启动失败
    ETASKS_QUEUE_FULL,                          // 委托任务队列已满
    ETASKS_WAIT_TIMEOUT,                        // 委托任务wait超时
    ETASKS_WAIT_DEFERRED,                       // 委托任务wait延期
    ETASKS_POST_SYNCTASK_FAIL,                  // 生成同步任务失败
    ETASKS_POST_ASYNCTASK_FAIL,                 // 生成异步任务失败
    DUMP_PARAM_ERR                              // DUMP参数错误
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
    EPOLL_CREATE_FAIL,                          // EPOLL创建失败
    EPOLL_MODIFY_FAIL,                          // 修改EPOLL失败
    STREAM_BUF_WRITE_FAIL,                      // 流缓冲写入失败
    VAL_NOT_EXP,                                // 值不符合预期
    MEM_NOT_ENOUGH,                             // 没有足够的内存
    MEM_OUT_OF_BOUNDS,                          // 内存越界
    SESSION_NOT_FOUND,                          // 没有找到session
    INVALID_MONITOR_MON                         // 监听增加失败
};

enum REGISTER {
    MMI_STANDARD_EVENT_SUCCESS = 1,
    MMI_STANDARD_EVENT_INVALID_PARAM = -1,
};

enum MMI_SERVICE_STATUS {
    MMI_SERVICE_INVALID = -1, // 多模服务不存在，多模输入服务异常
};
} // namespace MMI
} // namespace OHOS
#endif // ERROR_MULTIMODAL_H