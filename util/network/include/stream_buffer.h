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
#ifndef STREAM_BUFFER_H
#define STREAM_BUFFER_H

#include <cstdint>
#include <string>
#include <vector>

#include "nocopyable.h"
#include "securec.h"

#include "config_multimodal.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
class StreamBuffer {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "StreamBuffer"};
public:
    StreamBuffer() = default;
    DISALLOW_MOVE(StreamBuffer);
    virtual ~StreamBuffer() = default;
    explicit StreamBuffer(const StreamBuffer &buf);
    virtual StreamBuffer &operator=(const StreamBuffer &other);
    
    void Reset();
    void Clean();
    bool SeekReadPos(int32_t n);

    bool Read(std::string &buf);
    bool Write(const std::string &buf);

    bool Read(StreamBuffer &buf);
    bool Write(const StreamBuffer &buf);

    bool Read(char *buf, size_t size);
    virtual bool Write(const char *buf, size_t size);

    bool IsEmpty() const;
    size_t Size() const;
    int32_t UnreadSize() const;
    int32_t GetAvailableBufSize() const;

    bool ChkRWError() const;
    const std::string &GetErrorStatusRemark() const;
    const char *Data() const;

    template<typename T>
    bool Read(T &data);
    template<typename T>
    bool Write(const T &data);
    template<typename T>
    bool Read(std::vector<T> &data);
    template<typename T>
    bool Write(const std::vector<T> &data);

    const char *ReadBuf() const;
    const char *WriteBuf() const;

    template<typename T>
    StreamBuffer &operator >> (T &data);
    template<typename T>
    StreamBuffer &operator << (const T &data);

protected:
    bool Clone(const StreamBuffer &buf);

protected:
    enum class ErrorStatus {
        ERROR_STATUS_OK,
        ERROR_STATUS_READ,
        ERROR_STATUS_WRITE,
    };
    ErrorStatus rwErrorStatus_ = ErrorStatus::ERROR_STATUS_OK;
    int32_t rCount_ { 0 };
    int32_t wCount_ { 0 };

    int32_t rPos_ { 0 };
    int32_t wPos_ { 0 };
    char szBuff_[MAX_STREAM_BUF_SIZE+1] = {};
};

template<typename T>
bool StreamBuffer::Read(T &data)
{
    if (!Read(reinterpret_cast<char *>(&data), sizeof(data))) {
        MMI_HILOGE("[%{public}s] size:%{public}zu count:%{public}d,errCode:%{public}d",
            GetErrorStatusRemark().c_str(), sizeof(data), rCount_ + 1, STREAM_BUF_READ_FAIL);
        return false;
    }
    return true;
}

template<typename T>
bool StreamBuffer::Write(const T &data)
{
    if (!Write(reinterpret_cast<const char *>(&data), sizeof(data))) {
        MMI_HILOGE("[%{public}s] size:%{public}zu,count:%{public}d,errCode:%{public}d",
            GetErrorStatusRemark().c_str(), sizeof(data), wCount_ + 1, STREAM_BUF_WRITE_FAIL);
        return false;
    }
    return true;
}

template<typename T>
bool StreamBuffer::Read(std::vector<T> &data)
{
    int32_t size = 0;
    if (!Read(size)) {
        MMI_HILOGE("Read vector size error");
        return false;
    }
    if (size < 0 || size > MAX_VECTOR_SIZE) {
        MMI_HILOGE("Read vector size:%{public}d error", size);
        return false;
    }
    for (int32_t i = 0; i < size; i++) {
        T val;
        if (!Read(val)) {
            MMI_HILOGE("Read vector data error");
            return false;
        }
        data.push_back(val);
    }
    return true;
}

template<typename T>
bool StreamBuffer::Write(const std::vector<T> &data)
{
    if (data.size() > INT32_MAX) {
        MMI_HILOGE("Vector exceeds the max range");
        return false;
    }
    int32_t size = static_cast<int32_t>(data.size());
    if (!Write(size)) {
        MMI_HILOGE("Write vector size error");
        return false;
    }
    for (const auto &item : data) {
        if (!Write(item)) {
            MMI_HILOGE("Write vector data error");
            return false;
        }
    }
    return true;
}

template<typename T>
StreamBuffer &StreamBuffer::operator>>(T &data)
{
    if (!Read(data)) {
        MMI_HILOGW("Read data failed");
    }
    return *this;
}

template<typename T>
StreamBuffer &StreamBuffer::operator<<(const T &data)
{
    if (!Write(data)) {
        MMI_HILOGW("Write data failed");
    }
    return *this;
}
} // namespace MMI
} // namespace OHOS
#endif // STREAM_BUFFER_H