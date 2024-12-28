/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef EXTRA_DATA_H
#define EXTRA_DATA_H

#include <vector>

namespace OHOS {
namespace MMI {
struct ExtraData {
    /*
     * buffer的最大个数
     *
     * @since 9
     */
    static constexpr int32_t MAX_BUFFER_SIZE = 1024;
    /*
     * 是否添加buffer信息
     *
     * @since 9
     */
    bool appended { false };
    /*
     * buffer信息
     *
     * @since 9
     */
    std::vector<uint8_t> buffer;
    /*
     * 拖拽工具类型
     *
     * @since 9
     */
    int32_t toolType{ 0 };
    /*
     * 事件类型
     *
     * @since 9
     */
    int32_t sourceType { -1 };
    /*
     * 事件触发的pointer id
     *
     * @since 9
     */
    int32_t pointerId { -1 };
    /*
     * 当前拖拽实例的标识
     *
     * @since 13
     */
    int32_t pullId { -1 };
    /*
     * 开始拖拽实例的事件id
     *
     * @since 13
     */
    int32_t eventId { -1 };
    /*
     * 使用硬光标绘制功能
     *
     * @since 13
     */
    bool drawCursor { false };
};
} // namespace MMI
} // namespace OHOS
#endif // EXTRA_DATA_H