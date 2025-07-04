/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef PLUGIN_STAGE_H
#define PLUGIN_STAGE_H

#include "key_event.h"
#include "pointer_event.h"
#include "axis_event.h"
#include "input_device.h"
#include "libinput.h"

namespace OHOS {
namespace MMI {
//  可以用于注册插件的阶段枚举
enum class InputPluginStage {
    INPUT_GLOBAL_INIT = 0,   // 全局预留，不允许注册
    INPUT_DEV_ADDED = 3,     // 输入设备增加，该Hook不改变行为，仅感知变化
    INPUT_DEV_REMOVEED = 6,  // 输入设备删除，该Hook不改变行为，仅感知变化
    INPUT_BEFORE_LIBINPUT_ADAPTER_ON_EVENT = 12,
    INPUT_AFTER_LIBINPUT_ADAPTER_ON_EVENT = 13,
    INPUT_BEFORE_NORMALIZED = 15,
    INPUT_AFTER_NORMALIZED,        // 支持添加Hook
    INPUT_DEVICE_CHANGE = 20,      // 支持添加Hook，该Hook不改变行为，仅感知变化
    INPUT_BEFORE_FILTER = 25,      // 支持添加Hook
    INPUT_AFTER_FILTER,            // 支持添加Hook
    INPUT_BEFORE_INTERCEPT = 30,   // 支持添加Hook
    INPUT_AFTER_INTERCEPT,         // 支持添加Hook
    INPUT_BEFORE_KEYCOMMAND = 35,  // 支持添加Hook，仅在按键时会触发
    INPUT_AFTER_KEYCOMMAND,        // 支持添加Hook，，仅在按键时会触发
    INPUT_BEFORE_MONITOR = 40,     // 支持添加Hook
    INPUT_AFTER_MONITOR,           // 支持添加Hook
    INPUT_STAGE_BUTT,
};

//  可以用于插件返回结论
enum class PluginResult {
    Error = -1,             // 出错，视为未消费
    UseNeedReissue = 0,     // 0:消费，不向后传递，如果中间和结束事件被消费，则框架补发cancel；
    NotUse,                 // 1:未消费，继续向后派发
    UseNoNeedReissue,       // 2:消费，中间事件由插件补发对应事件，无需框架补发cancel
};

// 事件派发阶段，该字段用于特殊定制，需要跳过中间环节往后派发事件的场景，但是不允许往前派发事件
enum class InputDispatchStage {
    Filter = 0,
    Intercept,
    KeyCommand,
    Monitor,
};

// 不能删除中间的方法，除非所有插件都不使用该方法且统一重新编译
// 独立的Context区分不同插件到多模方向的交互消息
// 插件处理事件的方式有消费掉、修改后往后传递、直接往后传递、拦截等待后续条件判定、生成新事件
// 事件是一条pipeline，在hook点处理完成后，不能返回hook点之前的流程；只能往后派发
// 仅支持在多模工作线程调用context里面的方法
struct IPluginContext {
    // 调用线程：多模工作线程， 数量要求：同时添加的timer个数不大于3个
    virtual int32_t AddTimer(std::function<void()> func, int32_t intervalMs, int32_t repeatCount) = 0;
    // 调用线程：多模工作线程
    virtual int32_t RemoveTimer(int32_t id) = 0;
    // 调用线程：多模工作线程, 避免在hook过程中调用该接口，以免形成死循环
    void DispatchEvent(std::shared_ptr<KeyEvent> keyEvent, InputDispatchStage  stage);
    // 调用线程：多模工作线程, 避免在hook过程中调用该接口，以免形成死循环
    void DispatchEvent(std::shared_ptr<PointerEvent> pointerEvent, InputDispatchStage stage);
    // 调用线程：多模工作线程, 避免在hook过程中调用该接口，以免形成死循环
    void DispatchEvent(std::shared_ptr<AxisEvent> AxisEvent, InputDispatchStage stage);
    // libinputAdapter阶段专用
    virtual void DispatchEvent(libinput_event *event, int64_t frameTime) = 0;
};

/* 插件处理事件的方式有消费事件、修改后向后传递、直接向后传递、拦截等待后续条件判定、生成新事件
  *  param：libinput_event为标准libinput输出的时间类型
  *                InputEvent为通用事件类型，通过GetEventType获取具体的事件类型
  *  return value 为int32_t值，=0：消费，不向后传递，如果中间和结束事件被消费，则框架补发cancel；=1：未消费 ，继续向后传递， <0 出错，视为未消费；>1 预留，视为无效，，视为未消费
*/
struct IInputPlugin {
    virtual int32_t GetPriority() const = 0;
    virtual const std::string GetVersion() const = 0;
    virtual const std::string GetName() const = 0;
    virtual InputPluginStage GetStage() const = 0;
    virtual void DeviceWillAdded(std::shared_ptr<InputDevice> inputDevice){};
    virtual void DeviceDidAdded(std::shared_ptr<InputDevice> inputDevice){};
    virtual void DeviceWillRemoved(std::shared_ptr<InputDevice> inputDevice){};
    virtual void DeviceDidRemoved(std::shared_ptr<InputDevice> inputDevice){};
    // libinput 事件专用
    virtual PluginResult HandleEvent(libinput_event *event, int64_t frameTime) const = 0;
    // 性能约束：耗时小于特定时间，比如0.1ms
    virtual PluginResult HandleEvent(std::shared_ptr<KeyEvent> keyEvent, InputPluginStage stage) const = 0;
    virtual PluginResult HandleEvent(std::shared_ptr<PointerEvent> pointerEvent, InputPluginStage stage) const = 0;
    virtual PluginResult HandleEvent(std::shared_ptr<AxisEvent> axisEvent, InputPluginStage stage) const = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // PLUGIN_STAGE_H