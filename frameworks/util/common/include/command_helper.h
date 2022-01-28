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

#ifndef OHOS_COMMAND_HELPER_H
#define OHOS_COMMAND_HELPER_H

#include "string_ex.h"
#include "log.h"

namespace OHOS::MMI {
    class CommandHelper {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "MmiConsoleLog" };
    public:
        CommandHelper(const std::string& command) : command_(command)
        {
            SplitStr(command_, strSep_, splitParameters_);
            for (auto& i : splitParameters_) {
                std::string s = TrimStr(i, '\n');
                MMI_LOGI("##%s##", s.c_str());
            }
        }
        ~CommandHelper() = default;

        size_t GetParameterCount() const
        {
            return splitParameters_.size();
        }

        std::string GetParameterByPos(size_t pos)
        {
            if (splitParameters_.size() > pos) {
                return splitParameters_[pos];
            }

            return "";
        }
    private:
        std::string command_;
        std::vector<std::string> splitParameters_;
        std::string strSep_ = " ";
    };
} // namespace OHOS::MMI

#endif // OHOS_COMMAND_HELPER_H
