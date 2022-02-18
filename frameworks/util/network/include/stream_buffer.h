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
#include "securec.h"
#include "log.h"
#include "config_multimodal.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class StreamBuffer {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "StreamBuffer"};
public:
    StreamBuffer() {}
    StreamBuffer(const StreamBuffer& buf);
    virtual ~StreamBuffer() {}
    virtual StreamBuffer& operator=(const StreamBuffer& other);
    DISALLOW_MOVE(StreamBuffer);

    void Clean();
    bool SetReadIdx(uint32_t idx);

    bool Read(std::string& buf);
    bool Write(const std::string& buf);

    bool Read(StreamBuffer& buf);
    bool Write(const StreamBuffer& buf);

    bool Read(char *buf, size_t size);
    bool Write(const char *buf, size_t size);

    bool IsEmpty();
    size_t Size() const;
    size_t UnreadSize() const;

    bool ChkError() const;
    const std::string& GetErrorStatusRemark() const;
    const char *Data() const;

    template<typename T>
    bool Read(T& data);
    template<typename T>
    bool Write(const T& data);

    template<typename T>
    StreamBuffer& operator >> (T& data);
    template<typename T>
    StreamBuffer& operator << (const T& data);

protected:
    const char *ReadBuf() const;
    const char *WriteBuf() const;
    bool Clone(const StreamBuffer& buf);

protected:
    enum class ErrorStatus : int8_t {
        ES_OK,
        ES_READ,
        ES_WRITE,
    };
    ErrorStatus rwErrorStatus_ = ErrorStatus::ES_OK;
    int16_t rCount_ = 0;
    int16_t wCount_ = 0;

    uint32_t rIdx_ = 0;
    uint32_t wIdx_ = 0;
    char szBuff_[MAX_STREAM_BUF_SIZE] = {};
};

template<typename T>
bool StreamBuffer::Read(T &data)
{
    if (!Read(reinterpret_cast<char *>(&data), sizeof(data))) {
        MMI_LOGE("[%{public}s] size:%{public}zu count:%{public}d,errCode:%{public}d",
            GetErrorStatusRemark().c_str(), sizeof(data), rCount_+1, STREAM_BUF_READ_FAIL);
        return false;
    }
    return true;
}

template<typename T>
bool StreamBuffer::Write(const T &data)
{
    if (!Write(reinterpret_cast<char *>(const_cast<T *>(&data)), sizeof(data))) {
        MMI_LOGE("[%{public}s] size:%{public}zu,count:%{public}d,errCode:%{public}d",
            GetErrorStatusRemark().c_str(), sizeof(data), wCount_+1, STREAM_BUF_WRITE_FAIL);
        return false;
    }
    return true;
}

template<typename T>
StreamBuffer &StreamBuffer::operator>>(T &data)
{
    CK(Read(data), STREAM_BUF_READ_FAIL);
    return *this;
}

template<typename T>
StreamBuffer &StreamBuffer::operator<<(const T &data)
{
    CK(Write(data), STREAM_BUF_WRITE_FAIL);
    return *this;
}
} // namespace MMI
} // namespace OHOS
#endif // STREAM_BUFFER_H