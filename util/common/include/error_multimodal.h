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

#ifndef ERROR_MULTIMODAL_H
#define ERROR_MULTIMODAL_H

#include <errors.h>

namespace OHOS {
namespace MMI {
inline constexpr int32_t ERROR_UNSUPPORT { -2 };
inline constexpr int32_t ARGV_VALID { 2 };
inline constexpr int32_t ERROR_NO_PERMISSION { 201 };
inline constexpr int32_t ERROR_NOT_SYSAPI { 202 };
inline constexpr int32_t ERROR_DEVICE_NOT_EXIST { 3900001 };

enum {
    MODULE_CLIENT = 0x00,
    MODULE_EVENT_SIMULATE = 0x01,
    MODULE_SERVER = 0x02,
    MODULE_UTIL = 0x03
};

enum {
    // 文件打开失败
    FILE_OPEN_FAIL = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_EVENT_SIMULATE),
    // 流缓冲读取失败
    STREAM_BUF_READ_FAIL,
    // 事件注册失败
    EVENT_REG_FAIL,
    // 参数注入失败
    PARAM_INPUT_FAIL
};

enum {
    // 发送消息失败
    MSG_SEND_FAIL = 0x3E20000, //ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_SERVER),
    // 未知的事件
    UNKNOWN_EVENT,
    // 空指针
    ERROR_NULL_POINTER,
    // libinput初始化失败
    LIBINPUT_INIT_FAIL,
    // 无效的输入参数
    PARAM_INPUT_INVALID,
    // memcpy安全函数错误
    MEMCPY_SEC_FUN_FAIL,
    // 键盘事件封装失败
    KEY_EVENT_PKG_FAIL,
    // 多设备相同事件返回标志
    MULTIDEVICE_SAME_EVENT_MARK,
    // GESTURE_SWIPE事件封装失败
    GESTURE_EVENT_PKG_FAIL,
    // SA_Service初始化错误
    SASERVICE_INIT_FAIL,
    // 增加session错误
    ADD_SESSION_FAIL,
    // make_shared错误
    MAKE_SHARED_FAIL,
    // fcntl 函数调用错误
    FCNTL_FAIL,
    // 写入数据错误
    PACKET_WRITE_FAIL,
    // 读取数据错误
    PACKET_READ_FAIL,
    // 初始化画鼠标失败
    POINTER_DRAW_INIT_FAIL,
    // 多模服务未启动
    MMISERVICE_NOT_RUNNING,
    // 代理任务启动失败
    ETASKS_INIT_FAIL,
    // 委托任务wait超时
    ETASKS_WAIT_TIMEOUT,
    // 委托任务wait延期
    ETASKS_WAIT_DEFERRED,
    // 生成同步任务失败
    ETASKS_POST_SYNCTASK_FAIL,
    // 生成异步任务失败
    ETASKS_POST_ASYNCTASK_FAIL,
    // DUMP参数错误
    DUMP_PARAM_ERR,
    // 过滤器增加失败
    ERROR_FILTER_ADD_FAIL,
    // buffer过长失败
    ERROR_OVER_SIZE_BUFFER,
};

enum {
    // 非标准化事件
    NON_STD_EVENT = ErrCodeOffset(SUBSYS_MULTIMODAINPUT, MODULE_UTIL),
    // 未处理的消息
    UNPROC_MSG,
    // 未知消息ID
    UNKNOWN_MSG_ID,
    // EPOLL创建失败
    EPOLL_CREATE_FAIL,
    // 修改EPOLL失败
    EPOLL_MODIFY_FAIL,
    // 流缓冲写入失败
    STREAM_BUF_WRITE_FAIL,
    // 值不符合预期
    VAL_NOT_EXP,
    // 没有足够的内存
    MEM_NOT_ENOUGH,
    // 内存越界
    MEM_OUT_OF_BOUNDS,
    // 没有找到session
    SESSION_NOT_FOUND,
    // 监听增加失败
    INVALID_MONITOR_MON
};
} // namespace MMI
} // namespace OHOS
#endif // ERROR_MULTIMODAL_H
