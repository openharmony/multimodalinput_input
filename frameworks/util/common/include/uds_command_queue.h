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
#ifndef UDS_COMMAND_QUEUE_H
#define UDS_COMMAND_QUEUE_H

#include <mutex>
#include <list>
#include "singleton.h"

namespace OHOS {
namespace MMI {
class UdsCommandQueue {
    DECLARE_SINGLETON(UdsCommandQueue);
public:
    size_t GetSize() const;
    std::string PopCommand();
    void AddCommand(const std::string &command);
protected:
    std::mutex mux_;
    std::list<std::string> commandQueue_;
};
} // namespace MMI
} // namespace OHOS
#endif // UDS_COMMAND_QUEUE_H