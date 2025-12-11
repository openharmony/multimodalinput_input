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

#include "input_sendevent_command.h"

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

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputSendeventCommand"

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t SEND_EVENT_ARGC { 6 };
constexpr uint32_t INPUT_TYPE_LENGTH { 5 };
constexpr uint32_t INPUT_CODE_LENGTH { 5 };
constexpr uint32_t INPUT_VALUE_LENGTH { 11 };
} // namespace

int32_t InputSendeventCommand::HandleSendEventCommand(int32_t argc, char** argv)
{
    InputSendeventCommand command;
    if (!command.SendEventOption(argc, argv)) {
        std::cerr << "please use 'uinput sendevent <device_node> <type> <code> <value>'" << std::endl;
        return RET_ERR;
    };
    int32_t ret = command.RunSendEvent();
    return ret;
}

bool InputSendeventCommand::SendEventOption(int32_t argc, char** argv)
{
    CALL_DEBUG_ENTER;
    if (argc != SEND_EVENT_ARGC) {
        std::cerr << "Wrong number of input parameters" << std::endl;
        return false;
    }

    std::string deviceNode = argv[++optind];
    if (!(CheckDevice(deviceNode))) {
        std::cerr << "Input error in device node, deviceNode:" << deviceNode.c_str() << std::endl;
        return false;
    }

    std::string inputType = argv[++optind];
    if (!(CheckType(inputType))) {
        std::cerr << "Input error in type, type:" << inputType.c_str() << std::endl;
        return false;
    }

    std::string inputCode = argv[++optind];
    if (!(CheckCode(inputCode))) {
        std::cerr << "Input error in code, code:" << inputCode.c_str() << std::endl;
        return false;
    }

    std::string inputValue = argv[++optind];
    if (!(CheckValue(inputValue))) {
        std::cerr << "Input error in value, value:" << inputValue.c_str() << std::endl;
        return false;
    }
    return true;
}

bool InputSendeventCommand::CheckValue(const std::string &inputValue)
{
    if ((inputValue.length()) > INPUT_VALUE_LENGTH) {
        return false;
    }
    bool isValueNumber = std::regex_match(inputValue, std::regex("-?(\\d+)"));
    if (isValueNumber) {
        int64_t numberValue = 0;
        auto [ptr, ec] = std::from_chars(inputValue.data(), inputValue.data() + inputValue.size(), numberValue);
        if (ec == std::errc() && (numberValue >= INT32_MIN) && (numberValue <= INT32_MAX)) {
            inputValue_ = numberValue;
            return true;
        }
    }
    return false;
}

bool InputSendeventCommand::CheckCode(const std::string &inputCode)
{
    if ((inputCode.length()) > INPUT_CODE_LENGTH) {
        return false;
    }
    bool isCodeNumber = std::regex_match(inputCode, std::regex("\\d+"));
    if (isCodeNumber) {
        uint16_t numberCode = 0;
        auto [ptr, ec] = std::from_chars(inputCode.data(), inputCode.data() + inputCode.size(), numberCode);
        if (ec == std::errc() && numberCode <= UINT16_MAX) {
            inputCode_ = numberCode;
            return true;
        }
    }
    return false;
}

bool InputSendeventCommand::CheckType(const std::string &inputType)
{
    if ((inputType.length()) > INPUT_TYPE_LENGTH) {
        return false;
    }
    bool isTypeNumber = std::regex_match(inputType, std::regex("\\d+"));
    if (isTypeNumber) {
        uint16_t numberType = 0;
        auto [ptr, ec] = std::from_chars(inputType.data(), inputType.data() + inputType.size(), numberType);
        if (ec == std::errc() && numberType <= UINT16_MAX) {
            inputType_ = numberType;
            return true;
        }
    }
    return false;
}

bool InputSendeventCommand::CheckDevice(const std::string &deviceNode)
{
    if (deviceNode.empty()) {
        return false;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(deviceNode.c_str(), realPath) == nullptr) {
        return false;
    }
    deviceNode_ = realPath;
    return true;
}

int32_t InputSendeventCommand::RunSendEvent()
{
    struct timeval tm;
    gettimeofday(&tm, 0);
    struct input_event event = {};
    event.input_event_sec = tm.tv_sec;
    event.input_event_usec = tm.tv_usec;
    event.type = inputType_;
    event.code = inputCode_;
    event.value = inputValue_;
    int32_t fd = open(deviceNode_.c_str(), O_RDWR);
    if (fd < 0) {
        std::cerr << "Open device node failed, path:" << deviceNode_.c_str() << std::endl;
        return RET_ERR;
    }
    int32_t ret = write(fd, &event, sizeof(event));
    if (ret != sizeof(event)) {
        std::cerr << "Send event to device node failed" << std::endl;
        close(fd);
        return RET_ERR;
    }
    close(fd);
    return RET_OK;
}
} // namespace MMI
} // namespace OHOS