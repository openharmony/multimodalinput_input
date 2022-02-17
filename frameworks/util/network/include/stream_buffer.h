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
#ifndef STREAM_BUFFER_H
#define STREAM_BUFFER_H

#include <stdint.h>
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
    explicit StreamBuffer();
    StreamBuffer(const StreamBuffer& buf);
    virtual ~StreamBuffer() {}
    virtual StreamBuffer& operator= (const StreamBuffer& other);
    DISALLOW_MOVE(StreamBuffer);

    void ResetBuf();

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

    template<typename T>
    bool Read(T& data);

    template<typename T>
    bool Write(const T& data);

    const char *Data() const;

    template<typename T>
    StreamBuffer& operator >> (T& data);

    template<typename T>
    StreamBuffer& operator << (const T& data);

protected:
    const char *ReadBuf() const;

    const char *WriteBuf() const;

    bool Clone(const StreamBuffer& buf);

protected:
    uint32_t rIdx_ = 0;
    uint32_t wIdx_ = 0;
    char szBuff_[MAX_STREAM_BUF_SIZE] = {};
};

template<typename T>
bool OHOS::MMI::StreamBuffer::Write(const T &data)
{
    return Write(reinterpret_cast<char *>(const_cast<T *>(&data)), sizeof(data));
}

template<typename T>
StreamBuffer &OHOS::MMI::StreamBuffer::operator<<(const T &data)
{
    CK(Write(data), STREAM_BUF_WRITE_FAIL);
    return *this;
}

template<typename T>
bool OHOS::MMI::StreamBuffer::Read(T &data)
{
    return Read(reinterpret_cast<char *>(&data), sizeof(data));
}

template<typename T>
StreamBuffer &OHOS::MMI::StreamBuffer::operator>>(T &data)
{
    CK(Read(data), STREAM_BUF_READ_FAIL);
    return *this;
}
} // namespace MMI
} // namespace OHOS
#endif // STREAM_BUFFER_H