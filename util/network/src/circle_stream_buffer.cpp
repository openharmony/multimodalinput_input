/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "circle_stream_buffer.h"

namespace OHOS {
namespace MMI {
void CircleStreamBuffer::MoveMemoryToBegin()
{
    int32_t unreadSize = UnreadSize();
    if (unreadSize > 0 && rIdx_ > 0) {
        int32_t idx = 0;
        for (int32_t i = rIdx_; i <= wIdx_; i++) {
            szBuff_[idx] = szBuff_[i];
            szBuff_[i] = '\0';
            idx++;
        }
    }
    MMI_HILOGD("unreadSize:%{public}d rIdx:%{public}d wIdx:%{public}d", unreadSize, rIdx_, wIdx_);
    rIdx_ = 0;
    wIdx_ = unreadSize;
}

bool CircleStreamBuffer::CheckWrite(size_t size)
{
    int32_t aviSize = AvailableSize();
    if (size > aviSize && rIdx_ > 0) {
        MoveMemoryToBegin();
        aviSize = AvailableSize();
    }
    return (aviSize >= size);
}

bool CircleStreamBuffer::Write(const char *buf, size_t size)
{
    if (!CheckWrite(size)) {
        MMI_HILOGE("Out of buffer memory, availableSize:%{public}d, size:%{public}zu,"
            "unreadSize:%{public}d, rIdx:%{public}d, wIdx:%{public}d",
            AvailableSize(), size, UnreadSize(), rIdx_, wIdx_);
        return false;
    }
    return StreamBuffer::Write(buf, size);
}
} // namespace MMI
} // namespace OHOS