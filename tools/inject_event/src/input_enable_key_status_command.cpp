/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "input_enable_key_status_command.h"

#include <cctype>
#include <charconv>
#include <cstdio>
#include <fcntl.h>
#include <iostream>
#include <regex>
#include <string>
#include <typeinfo>
#include <unistd.h>
#include <linux/input.h>

#include "error_multimodal.h"
#include "proto.h"
#include "util.h"
#include "input_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEnableKeyStatusCommand"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MIN_ARGC { 3 };
constexpr int32_t MAX_ARGC { 4 };
constexpr uint32_t ENABLE_LENGTH { 1 };
constexpr uint32_t TIMEOUT_LENGTH { 2 };
constexpr int32_t S_TO_MS { 1000 };
} // namespace

int32_t InputEnableKeyStatusCommand::HandleEnableKeyStatusCommand(int32_t argc, char** argv)
{
    InputEnableKeyStatusCommand command;
    if (!command.EnableKeyStatusOption(argc, argv)) {
        std::cerr << "please use 'uinput enable_key_status <enable> [timeout]'" << std::endl;
        return RET_ERR;
    };
    int32_t ret = command.RunEnableKeyStatus();
    return ret;
}

bool InputEnableKeyStatusCommand::EnableKeyStatusOption(int32_t argc, char** argv)
{
    CALL_DEBUG_ENTER;
    if (argc < MIN_ARGC || argc > MAX_ARGC) {
        std::cerr << "Wrong number of input parameters" << std::endl;
        return false;
    }

    std::string enable = argv[++optind];
    if (!(CheckEnable(enable))) {
        std::cerr << "Input error in enable, enable:" << enable.c_str() << std::endl;
        return false;
    }

    if (argc == optind + 1) {
        return true;
    }

    std::string timeout = argv[++optind];
    if (!(CheckTimeout(timeout))) {
        std::cerr << "Input error in timeout, timeout:" << timeout.c_str() << std::endl;
        return false;
    }
    return true;
}

bool InputEnableKeyStatusCommand::CheckEnable(const std::string &enable)
{
    if ((enable.length()) > ENABLE_LENGTH) {
        std::cerr << "The value entered is out of range, enable:" << enable.c_str() << std::endl;
        return false;
    }
    enable_ = (enable == "1");
    return enable == "0" || enable == "1";
}

bool InputEnableKeyStatusCommand::CheckTimeout(const std::string &timeout)
{
    if ((timeout.length()) > TIMEOUT_LENGTH) {
        std::cerr << "The value entered is out of range, timeout:" << timeout.c_str() << std::endl;
        return false;
    }
    bool isInteger = IsInteger(timeout.c_str());
    if (isInteger) {
        int32_t numberTimeout = MAX_TIMEOUT_MS / S_TO_MS;
        auto [ptr, ec] = std::from_chars(timeout.data(), timeout.data() + timeout.size(), numberTimeout);
        if (ec != std::errc()) {
            std::cerr << "Invalid timeout value, timeout:" << timeout.c_str() << std::endl;
            return false;
        }
        if (numberTimeout <= 0) {
            return false;
        }
        if (numberTimeout * S_TO_MS > MAX_TIMEOUT_MS) {
            return false;
        }
        timeout_ = numberTimeout * S_TO_MS;
    }
    return isInteger;
}

int32_t InputEnableKeyStatusCommand::RunEnableKeyStatus()
{
    auto inputManager = InputManager::GetInstance();
    if (inputManager == nullptr) {
        std::cerr << "InputManager instance is null" << std::endl;
        return RET_ERR;
    }
    int32_t ret = inputManager->SetKeyStatusRecord(enable_, timeout_);
    if (ret != RET_OK) {
        std::cerr << "Failed to enable key status record" << std::endl;
    }
    return ret;
}
} // namespace MMI
} // namespace OHOS