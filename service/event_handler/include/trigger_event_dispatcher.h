/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef TRIGGER_EVENT_DISPATCHER_H
#define TRIGGER_EVENT_DISPATCHER_H

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <set>
#include <cstdint>

#include "key_event.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {

// KeyCommandTriggerType 枚举定义
enum KeyCommandTriggerType {
    PRESSED = 1,         // 首次按下触发
    REPEAT_PRESSED = 2,  // 重复按下触发
    ALL_RELEASED = 3      // 所有键释放时触发
};

class TriggerEventDispatcher {
public:
    static TriggerEventDispatcher* GetInstance();
    ~TriggerEventDispatcher() = default;

    // 判断是否应该分发事件
    bool ShouldDispatch(std::shared_ptr<KeyOption> keyOption,
                       std::shared_ptr<KeyEvent> keyEvent);

    // 判断是否应该消费事件（不向后传递）
    bool ShouldConsume(std::shared_ptr<KeyOption> keyOption,
                      std::shared_ptr<KeyEvent> keyEvent);

    // 清理订阅状态
    void ClearSubscribeState(const std::string& subscribeKey);

private:
    TriggerEventDispatcher() = default;
    TriggerEventDispatcher(const TriggerEventDispatcher&) = delete;
    TriggerEventDispatcher& operator=(const TriggerEventDispatcher&) = delete;

    // PRESSED 模式分发判断
    bool ShouldDispatchPRESSED(std::shared_ptr<KeyOption> keyOption,
                              std::shared_ptr<KeyEvent> keyEvent);

    // REPEAT_PRESSED 模式分发判断
    bool ShouldDispatchREPEAT_PRESSED(std::shared_ptr<KeyOption> keyOption,
                                    std::shared_ptr<KeyEvent> keyEvent);

    // ALL_RELEASED 模式分发判断
    bool ShouldDispatchALL_RELEASED(std::shared_ptr<KeyOption> keyOption,
                                    std::shared_ptr<KeyEvent> keyEvent);

    // 检查 preKeys 是否匹配
    bool MatchPreKeys(std::shared_ptr<KeyOption> keyOption,
                      std::shared_ptr<KeyEvent> keyEvent);

    // 检查 finalKeyDownDuration 条件
    bool CheckDuration(std::shared_ptr<KeyOption> keyOption,
                       std::shared_ptr<KeyEvent> keyEvent);

    // 检查是否在 duration 窗口内有其他按键
    bool HasOtherKeyPressedInWindow(const std::string& subscribeKey);

    // 记录 duration 窗口开始
    void StartDurationWindow(const std::string& subscribeKey, int32_t duration);

    // 标记 duration 窗口已通过
    void MarkDurationPassed(const std::string& subscribeKey);

private:
    // 检查duration窗口是否已通过
    bool CheckDurationWindowPassed(const std::string& subscribeKey);

    // 检查duration窗口内是否有其他按键
    bool CheckDurationWindowWithOtherKey(const std::string& subscribeKey);

private:
    std::mutex mutex_;

    // 状态跟踪
    std::map<std::string, bool> firstDownSent_;        // PRESSED 模式：是否已发送首次 down
    std::map<std::string, int64_t> downStartTime_;     // 首次 down 的时间戳
    std::map<std::string, bool> durationPassed_;       // duration 窗口是否已通过
    std::map<std::string, bool> hasOtherKey_;          // duration 窗口内是否有其他按键
};

} // namespace MMI
} // namespace OHOS

#endif // TRIGGER_EVENT_DISPATCHER_H
