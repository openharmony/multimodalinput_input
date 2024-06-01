/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef INPUT_TABLE_DUMP_H
#define INPUT_TABLE_DUMP_H

#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace OHOS {
namespace MMI {
constexpr size_t extraCharactersCount { 3 };
constexpr int32_t elementSpaceCount { 2 };

template<typename T>
inline size_t getElementLength(const T &element)
{
    std::ostringstream oss;
    oss << element;
    return oss.str().size();
}

template<typename... Titles, typename... Args>
inline std::vector<size_t> CalculateColumnWidths(const std::tuple<Titles...> &titles,
                                                 const std::vector<std::tuple<Args...>> &rows,
                                                 size_t &lineWidth)
{
    std::vector<size_t> widths(sizeof...(Titles), 0);
    auto updateWidths = [&widths](const auto &... field) {
        size_t index = 0;
        ((widths[index] = std::max(widths[index], getElementLength(field)), ++index), ...);
    };
    std::apply(updateWidths, titles);
    for (const auto &row: rows) {
        std::apply(updateWidths, row);
    }
    std::for_each(widths.begin(), widths.end(),
                  [&lineWidth](size_t width) { lineWidth += width + extraCharactersCount; });
    lineWidth += 1;
    return widths;
}

inline void PrintLine(std::ostream &os, const std::vector<size_t> &widths)
{
    os << "+";
    for (const size_t &width: widths) {
        os << std::setw(static_cast<int32_t>(width) + elementSpaceCount) << std::left << std::setfill('-') << "" << "+";
    }
    os << std::setfill(' ') << std::endl;
}

template<typename T>
inline void PrintCentered(std::ostream &os, const T &value, size_t width)
{
    std::ostringstream oss;
    oss << value;
    std::string str = oss.str();
    size_t padding_left = (width - str.size()) / 2;
    size_t padding_right = width - str.size() - padding_left;
    os << std::string(padding_left, ' ') << str << std::string(padding_right, ' ');
}

template<typename... Titles>
inline void PrintHeader(std::ostream &os, const std::vector<size_t> &widths, Titles... titles)
{
    os << "|";
    size_t index = 0;
    ((os << " ", PrintCentered(os, titles, widths[index++]), os << " |"), ...);
    os << std::endl;
}

template<typename... Args>
inline void PrintRow(std::ostream &os, const std::vector<size_t> &widths, Args... args)
{
    os << "|";
    size_t index = 0;
    ((os << " ", PrintCentered(os, args, widths[index++]), os << " |"), ...);
    os << std::endl;
}

template<typename... Titles, typename... Args>
inline void DumpFullTable(std::ostream &os, const std::string &tableName, const std::tuple<Titles...> &titles,
                          const std::vector<std::tuple<Args...>> &rows)
{
    static_assert(sizeof...(Titles) == sizeof...(Args), "Number of titles must match number of columns in each row");

    // 计算每一列的最大宽度
    size_t lineWidth = 0;
    std::vector<size_t> widths = CalculateColumnWidths(titles, rows, lineWidth);

    // 打印表名称
    PrintCentered(os, tableName, lineWidth);
    os << std::endl;

    // 打印标题行
    PrintLine(os, widths);
    std::apply([&os, &widths](auto &&... args) { PrintHeader(os, widths, args...); }, titles);
    PrintLine(os, widths);

    // 打印每一行数据
    for (const auto &row: rows) {
        std::apply([&os, &widths](auto &&... args) { PrintRow(os, widths, args...); }, row);
        PrintLine(os, widths);
    }
}
} // namespace MMI
} // namespace OHOS
#endif //INPUT_TABLE_DUMP_H
