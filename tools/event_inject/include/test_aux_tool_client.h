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
#ifndef TEST_AUX_TOOL_CLIENT_H
#define TEST_AUX_TOOL_CLIENT_H
#include "test_aux_tool_msg_handler.h"
#include "singleton.h"
#include "msg_head.h"

namespace OHOS {
namespace MMI {
    constexpr int32_t AI_CODE_MAX = 33;
    constexpr uint32_t AUTO_ERGODIC_CODE = 1;
    constexpr uint32_t MANUAL_INPUT_CODE = 2;
    constexpr uint32_t EV_VALUE_DEFAULT = 1;
    constexpr uint32_t CMD_PARA_VALID_MIN = 2;
    constexpr uint32_t CMD_PARA_VALID_MAX = 4;
    constexpr uint32_t VIRTUAL_PARA_VALID_NUM = 5;
    constexpr uint32_t INPUT_DEVICE_CAP_AI_SENSOR = 8;

class TestAuxToolClient : public UDSClient, public OHOS::Singleton<OHOS::MMI::TestAuxToolClient> {
    using AiSensorData = std::vector<std::string>;
public:
    TestAuxToolClient() = default;
    ~TestAuxToolClient() = default;
    bool Start(bool detachMode);
    int32_t ExecuteAllCommand();

    uint32_t GetAiSensorAllowProcCodes(uint32_t item) const;

    int32_t Socket() override;

protected:
    void OnConnected() override;
    void OnDisconnected() override;
    void OnThreadLoop() override;

    bool IsFirstConnectFailExit() override;

protected:
    bool isRun_ = false;
    TestAuxToolMsgHandler cMsgHandler_;
};
} // namespace MMI
} // namespace OHOS

#endif // TEST_AUX_TOOL_CLIENT_H