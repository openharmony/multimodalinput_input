/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Description: The testing of KeyEvent injection
 * Author: h00580190
 * Create: 2022-1-11
 * Notes: No
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

#include "multimodal_event_handler.h"
#include <gtest/gtest.h>
#include "key_event_handler.h"
#include "mmi_client.h"
#include "mmi_token.h"
#include "run_shell_util.h"
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
using namespace OHOS;

namespace {
    constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
    constexpr int32_t SEC_TO_NANOSEC = 1000000000;
    constexpr int32_t TIME_WAIT_FOR_LOG = 50;
    constexpr int32_t N_TRIES_FOR_LOG = 20;
    const std::regex REGEX_FIND_PID(" ");
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MultimodalKeyEventTest" };
    static RunShellUtil g_runCommand;
}

class MultimodalKeyEventTest : public testing::Test {
public:
    static int64_t GetNanoTime();
    static bool FindCommand(const std::string &log, const std::string &command);
    static std::vector<std::string> SearchForLog(const std::string &command, bool noWait = false);
    static std::vector<std::string> SearchForLog(const std::string &command,
        const std::vector<std::string> &excludes, bool noWait = false);
};

int64_t MultimodalKeyEventTest::GetNanoTime()
{
    timespec time = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time);
    return static_cast<uint64_t>(time.tv_sec) * SEC_TO_NANOSEC + time.tv_nsec;
}

bool MultimodalKeyEventTest::FindCommand(const std::string &log, const std::string &command)
{
    std::ostringstream sCmd;
    std::string::size_type spos { 0 }, tpos;
    while (spos < command.size()) {
        tpos = command.find("\\", spos);
        if (tpos != std::string::npos) {
            if (((tpos + 1) < command.size()) &&
                ((command[tpos + 1] == '{') || (command[tpos + 1] == '}'))) {
                sCmd << command.substr(spos, tpos - spos);
            } else {
                sCmd << command.substr(spos, tpos - spos + 1);
            }
            spos = tpos + 1;
        } else {
            sCmd << command.substr(spos);
            spos = command.size();
        }
    }
    MMI_LOGD("[log]:%{public}s,[command]:%{public}s", log.c_str(), command.c_str());
    std::regex pattern(sCmd.str());
    return std::regex_search(log, pattern);
}

std::vector<std::string> MultimodalKeyEventTest::SearchForLog(const std::string &command, bool noWait)
{
    std::vector<std::string> excludes;
    return SearchForLog(command, excludes, noWait);
}

std::vector<std::string> MultimodalKeyEventTest::SearchForLog(const std::string &command,
    const std::vector<std::string> &excludes, bool noWait)
{
    MMI_LOGD("excludes.size():%{public}d", excludes.size());
    int32_t nTries { N_TRIES_FOR_LOG };
    std::vector<std::string> results;

    while (true) {
        std::vector<std::string> logs;
        (void)g_runCommand.RunShellCommand(command, logs);
        MMI_LOGD("logs.size():%{public}d", logs.size());
        for (auto &item : logs) {
            MMI_LOGD("[log]:%{public}s", item.c_str());
            if (FindCommand(item, command) &&
                (std::find(excludes.cbegin(), excludes.cend(), item) == excludes.cend())) {
                results.push_back(item);
            }
        }
        if (noWait || !results.empty() || (--nTries <= 0)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_LOG));
    }
    MMI_LOGD("results.size():%{public}d", results.size());
    return results;
}


HWTEST_F(MultimodalKeyEventTest, MultimodalEventHandler_InjectKeyEvent_001, TestSize.Level1)
{
    RunShellUtil runCommand;
    std::string command = "Inject keyCode = 2,action = 2";
    std::vector<std::string> slogs {SearchForLog(command, true)};
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    std::shared_ptr<OHOS::MMI::KeyEvent> injectDownEvent = OHOS::MMI::KeyEvent::Create(); 
    OHOS::MMI::KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    injectDownEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    std::shared_ptr<OHOS::MMI::KeyEvent> injectUpEvent = OHOS::MMI::KeyEvent::Create();
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    OHOS::MMI::KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    injectUpEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    MMI_LOGD("response:%{public}u", response);
    std::vector<std::string> tlogs {SearchForLog(command, slogs)};
    EXPECT_TRUE(!tlogs.empty());
}

HWTEST_F(MultimodalKeyEventTest, MultimodalEventHandler_InjectKeyEvent_002, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::KeyEvent> injectDownEvent = OHOS::MMI::KeyEvent::Create(); 
    int32_t downTime = -1;
    OHOS::MMI::KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_HOME);
    injectDownEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    MMI_LOGD("response:%{public}u", response);
    EXPECT_TRUE(response);
}

HWTEST_F(MultimodalKeyEventTest, MultimodalEventHandler_InjectKeyEvent_003, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::KeyEvent> injectDownEvent = OHOS::MMI::KeyEvent::Create(); 
    int32_t downTime = 0;
    OHOS::MMI::KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    injectDownEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    EXPECT_TRUE(response);

    std::shared_ptr<OHOS::MMI::KeyEvent> injectUpEvent = OHOS::MMI::KeyEvent::Create();
    OHOS::MMI::KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_BACK);
    injectUpEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
}

HWTEST_F(MultimodalKeyEventTest, MultimodalEventHandler_InjectKeyEvent_004, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::KeyEvent> injectDownEvent = OHOS::MMI::KeyEvent::Create(); 
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    OHOS::MMI::KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_UNKNOWN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_UNKNOWN);
    injectDownEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    MMI_LOGD("begin");
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    MMI_LOGD("end, response:%{public}u", response);
    EXPECT_TRUE(response < 0);
}

HWTEST_F(MultimodalKeyEventTest, MultimodalEventHandler_InjectKeyEvent_005, TestSize.Level1)
{
    std::shared_ptr<OHOS::MMI::KeyEvent> injectDownEvent = OHOS::MMI::KeyEvent::Create(); 
    int32_t downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    OHOS::MMI::KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_FN);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    injectDownEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_FN);
    injectDownEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_DOWN);
    injectDownEvent->AddPressedKeyItems(kitDown);
    if (injectDownEvent == nullptr) {
        MMI_LOGD("injectDownEvent is nullptr");
    }
    MMI_LOGD("MMIEventHdl.InjectEvent begin");
    int32_t response = MMIEventHdl.InjectEvent(injectDownEvent);
    MMI_LOGD("MMIEventHdl.InjectEvent end");
    EXPECT_TRUE(response);

    std::shared_ptr<OHOS::MMI::KeyEvent> injectUpEvent = OHOS::MMI::KeyEvent::Create();
    downTime = static_cast<int32_t>(GetNanoTime()/NANOSECOND_TO_MILLISECOND);
    OHOS::MMI::KeyEvent::KeyItem kitUp;
    kitUp.SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_FN);
    kitUp.SetPressed(false);
    kitUp.SetDownTime(downTime);
    injectUpEvent->SetKeyCode(OHOS::MMI::KeyEvent::KEYCODE_FN);
    injectUpEvent->SetKeyAction(OHOS::MMI::KeyEvent::KEY_ACTION_UP);
    injectUpEvent->RemoveReleasedKeyItems(kitUp);
    response = MMIEventHdl.InjectEvent(injectUpEvent);
    EXPECT_TRUE(response);
}
} // namespace