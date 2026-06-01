# KeyEvent rawCode 和 repeatCount 规格说明

## 1. 背景

`KeyEvent` 需要新增两个信息：

- `rawCode`：OpenHarmony 键值归一化之前的 libinput 原始按键码。
- `repeatCount`：同一次按键按住期间，由自动重复键机制生成的重复键次数。

本次修改必须保持现有键盘行为不变。尤其是现有 `IsRepeat()` 和 `IsRepeatKey()` 的语义不能改变。新增字段只作为补充观测数据，不能参与现有重复键决策逻辑。

本文档覆盖：

- `KeyEvent` 数据模型变更。
- libinput 归一化阶段的 `rawCode` 赋值。
- 自动重复键阶段的 `repeatCount` 赋值。
- `Parcel` 结构体序列化。
- 服务端到客户端 UDS/socket 序列化兼容。

本文档不覆盖 `intention/cooperate/plugin/` 下已经废弃的 cooperate `NetPacket` 链路。

## 2. 现有事件链路

键盘事件主链路如下：

```text
libinput keyboard event
 -> KeyEventNormalize::Normalize()
 -> EventNormalizeHandler::HandleKeyboardEvent()
 -> UpdateKeyEventHandlerChain()
 -> KeyAutoRepeat::SelectAutoRepeat()
 -> EventDispatchHandler::HandleKeyEvent()
 -> InputEventDataTransformation::KeyEventToNetPacket()
 -> UDSServer::SendMsg()
 -> ClientMsgHandler::OnKeyEvent()
 -> InputEventDataTransformation::NetPacketToKeyEvent()
 -> InputMgrImpl.OnKeyEvent()
```

其他客户端可见的按键路径也会复用 `InputEventDataTransformation::KeyEventToNetPacket()` 和 `NetPacketToKeyEvent()`，包括 monitor、pre-monitor、subscriber、input-active subscriber、interceptor 和 hook 链路。

## 3. 非目标

- 不修改 `intention/cooperate/plugin/` 下的键鼠穿越 cooperate 序列化代码。
- 除非另有需求，不向 JS SDK、C API 或公开应用 API 暴露这些字段。
- 不使用 `repeatCount` 替代或重新解释 `IsRepeat()`、`IsRepeatKey()`。
- 不改变事件顺序、分发目标选择、焦点行为或 ANR 行为。
- 不在热路径增加额外日志或高成本扫描。

## 4. 数据模型

### 4.1 KeyEvent::rawCode

`rawCode` 是事件级原始按键码。

默认值：

```text
-1
```

含义：

- `-1`：未知或不可用。
- 非负值：来自 libinput 的原始按键码。

`KeyEvent` 提供：

```cpp
int32_t GetRawCode() const;
void SetRawCode(int32_t rawCode);
```

### 4.2 KeyEvent::KeyItem::rawCode

`KeyItem::rawCode` 保存该按键项对应的原始按键码。

默认值：

```text
-1
```

`KeyItem` 提供：

```cpp
int32_t GetRawCode() const;
void SetRawCode(int32_t rawCode);
```

### 4.3 KeyEvent::repeatCount

`repeatCount` 是事件级字段，用于表示同一次按键按住期间自动重复键事件的次数。

默认值：

```text
0
```

含义：

| 事件场景 | repeatCount |
| --- | --- |
| 初始 `KEY_ACTION_DOWN` | `0` |
| 第 1 次自动重复生成事件 | `1` |
| 第 2 次自动重复生成事件 | `2` |
| 后续自动重复生成事件 | 逐次递增 |
| `KEY_ACTION_UP` | `0` |
| `KEY_ACTION_CANCEL` | `0` |
| 旧格式反序列化事件 | `0` |

`KeyEvent` 提供：

```cpp
int32_t GetRepeatCount() const;
void SetRepeatCount(int32_t repeatCount);
```

`SetRepeatCount()` 应保证保存值为非负数。如果传入负数，应归一化为 `0`。

`repeatCount` 不新增到 `KeyItem`。

原因：

- 该计数描述的是当前事件，不是单个按键项。
- 组合键事件可能包含多个 `KeyItem`，如果做成按键项级字段，会产生哪个 item 的重复次数有效的歧义。

## 5. 与现有重复键语义的兼容

现有字段仍然负责现有行为：

- `repeat_`
- `repeatKey_`

现有方法保持当前语义：

```cpp
bool IsRepeat() const;
void SetRepeat(bool repeat);
bool IsRepeatKey() const;
void SetRepeatKey(bool repeatKey);
```

禁止新增以下逻辑：

```cpp
SetRepeat(repeatCount > 0);
SetRepeatKey(repeatCount > 0);
```

必须保持以下行为不变：

- `EventNormalizeHandler::HandleKeyEvent()` 继续使用 `IsRepeat()` 判断是否进入 `KeyAutoRepeat::SelectAutoRepeat()`。
- `InputWindowsManager` 继续使用 `IsRepeatKey()` 处理现有与重复键相关的焦点逻辑。
- `PackageKeyUpEvent()` 中已有的 `SetRepeat(true)` 行为不因 `repeatCount` 改变。

## 6. 赋值设计

### 6.1 rawCode 赋值

`rawCode` 在键盘事件归一化相关路径赋值，包括普通 libinput 归一化事件和补偿抬键事件。

在 `KeyEventNormalize::Normalize()` 中：

```text
rawCode = libinput_event_keyboard_get_key(data)
keyEvent.SetRawCode(rawCode)
keyItem.SetRawCode(rawCode)
```

在 `KeyEventNormalize::PackageKeyUpEvent()` 中，入参 `rawCode` 来自 `pressedKeys_` 中记录的原始按键码。该函数生成的是设备禁用等场景下用于清理按键状态的补偿 `KEY_ACTION_UP` 事件，因此应使用该入参给 event 和 key item 赋值：

```text
keyEvent.SetRawCode(rawCode)
keyItem.SetRawCode(rawCode)
```

这样可以保证同一个物理按键序列中，正常 `KEY_ACTION_DOWN` 和补偿 `KEY_ACTION_UP` 都保留一致的原始按键码。

### 6.2 repeatCount 赋值

`repeatCount` 在 `KeyAutoRepeat` 中赋值，不在 `KeyEventNormalize::Normalize()` 中赋值。

原因：

- `Normalize()` 只能看到物理 libinput 事件。
- 重复键事件由 `KeyAutoRepeat` 生成。
- `KeyAutoRepeat` 持有定时器状态，能够准确统计已经生成的重复键次数。

`KeyAutoRepeat` 新增内部状态：

```cpp
int32_t repeatCount_ { 0 };
```

以下场景重置计数：

- 新的按键按住序列开始。
- 当前重复键被不同 `keyCode` 替换。
- 处理 `KEY_ACTION_UP`。
- 处理 `KEY_ACTION_CANCEL`。
- 重复键定时器被移除。
- `repeatKeyCode_` 被重置为非法值。

自动重复键定时器生成重复事件时递增计数：

```text
repeatCount_ = repeatCount_ + 1
keyEvent.SetRepeatCount(repeatCount_)
HandleKeyEvent(keyEvent)
```

第一个自动重复生成事件的 `repeatCount` 为 `1`。

### 6.3 重复按键示例

当前自动重复键是单重复键模型，同一时间只有一个 `repeatKeyCode_`。

#### 示例一：单键 A 持续按住

事件序列：

```text
A down
A repeat
A repeat
A repeat
A up
```

`repeatCount` 取值：

| 事件 | IsRepeatKey | repeatCount | 说明 |
| --- | --- | --- | --- |
| `A down` | 保持现有逻辑 | `0` | 初始物理按下事件 |
| 第 1 次 `A repeat` | 保持现有逻辑 | `1` | 第一次自动重复生成事件 |
| 第 2 次 `A repeat` | 保持现有逻辑 | `2` | 第二次自动重复生成事件 |
| 第 3 次 `A repeat` | 保持现有逻辑 | `3` | 第三次自动重复生成事件 |
| `A up` | 保持现有逻辑 | `0` | 抬键后计数清零 |

#### 示例二：A 按住后再按 B

事件序列：

```text
A down
A repeat
A repeat
B down
B repeat
B repeat
B up
A up
```

当前代码行为：

- `A down` 后，`repeatKeyCode_` 设置为 A，启动 A 的自动重复定时器。
- `B down` 到来时，如果 A 的重复定时器仍存在，且 B 与当前 `repeatKeyCode_` 不同，则移除 A 的定时器。
- 移除 A 的定时器后，`repeatKeyCode_` 切换为 B，并启动 B 的自动重复定时器。
- `B up` 后停止 B 的自动重复，计数清零。
- 当前逻辑不会在 `B up` 后自动恢复 A 的自动重复。

`repeatCount` 取值：

| 事件 | 当前重复键 | repeatCount | 说明 |
| --- | --- | --- | --- |
| `A down` | A | `0` | A 初始物理按下 |
| 第 1 次 `A repeat` | A | `1` | A 第一次自动重复 |
| 第 2 次 `A repeat` | A | `2` | A 第二次自动重复 |
| `B down` | B | `0` | B 按下打断 A 的自动重复，B 重新开始计数 |
| 第 1 次 `B repeat` | B | `1` | B 第一次自动重复 |
| 第 2 次 `B repeat` | B | `2` | B 第二次自动重复 |
| `B up` | 无 | `0` | B 自动重复停止并清零 |
| `A up` | 无 | `0` | A 普通抬键，不恢复 A 的重复计数 |

该示例中，`repeatCount` 跟随当前 `repeatKeyCode_`。当 B 打断 A 后，A 的重复计数结束，B 从 `0` 重新开始，并在 B 的自动重复事件中从 `1` 开始递增。

## 7. Parcel 序列化

### 7.1 需求

`KeyEvent::WriteToParcel()` 和 `KeyEvent::ReadFromParcel()` 需要携带：

- `KeyEvent::rawCode`
- `KeyEvent::KeyItem::rawCode`
- `KeyEvent::repeatCount`

不能修改旧序列化字段顺序。

### 7.2 结构体序列化格式

`Parcel` 序列化与 SE 结构体序列化方式对齐，不使用 `extFlags`、扩展版本或 TLV 结构。

新增字段按结构体字段顺序直接写入。建议字段顺序为：

```text
legacy KeyEvent fields
rawCode
rawCodeSize
keyItemRawCode[0]
keyItemRawCode[1]
...
repeatCount
```

### 7.3 写入规则

`WriteToParcel()` 先写入现有字段。

然后按固定顺序写入：

```text
rawCode
rawCodeSize
keyItemRawCodes...
repeatCount
```

### 7.4 读取规则

`ReadFromParcel()` 先读取现有字段。

然后：

- 如果剩余可读字节不足最小新增字段长度，说明是旧格式 Parcel 或新增字段尾部不完整，直接返回成功，`rawCode`、`KeyItem::rawCode` 和 `repeatCount` 保持默认值。
- 按固定顺序读取 `rawCode`。
- 读取 `rawCodeSize`。
- 按 `rawCodeSize` 读取 key-item rawCode。
- 读取 `repeatCount`。

校验要求：

- `rawCodeSize` 必须 `>= 0`。
- `rawCodeSize` 不能超过 `keys_.size()`。
- `rawCodeSize` 不能超过 `maxKeysSize`。
- 每次读取固定长度数据前，必须确认剩余可读字节足够。
- `repeatCount` 读取后必须为非负值。负数归一化为 `0`。

### 7.5 Parcel 兼容性

`Parcel` 序列化按结构体字段顺序直接对齐，不通过 `extFlags`、版本号或 TLV 实现扩展字段兼容。但新增字段位于旧字段尾部，读取端可以通过 `GetReadableBytes()` 判断是否存在新增尾部字段。

因此该部分要求：

- 旧格式 Parcel 没有新增尾部字段时，新版本 `ReadFromParcel()` 必须返回成功，并保持新增字段默认值。
- 新格式 Parcel 包含新增尾部字段时，新版本 `ReadFromParcel()` 按固定顺序读取。
- 新增尾部字段存在但长度不足或字段非法时，`ReadFromParcel()` 按可选字段处理，保持新增字段默认值并返回成功，不影响旧字段反序列化结果。
- 不改变旧字段顺序，不在旧字段中间插入字段。

该部分不能解决 C++ 对象布局兼容问题。新增类成员会改变 ABI 布局，不能通过只替换部分共享库来验证该修改。

## 8. UDS/socket 序列化

### 8.1 需求

服务端到客户端 socket 分发需要携带：

- `KeyEvent::rawCode`
- `KeyEvent::KeyItem::rawCode`
- `KeyEvent::repeatCount`

该链路主要由以下文件实现：

```text
util/common/src/input_event_data_transformation.cpp
```

核心函数：

```cpp
InputEventDataTransformation::KeyEventToNetPacket()
InputEventDataTransformation::NetPacketToKeyEvent()
```

### 8.2 关键兼容规则

不能把扩展字段直接作为旧 `KeyEventToNetPacket()` body 的一部分追加到函数末尾。

原因：

多个消息类型会在 `KeyEventToNetPacket()` 之后继续写入旧字段。

示例：

```text
ON_KEY_EVENT:
KeyEventToNetPacket()
fd
enhanceData
```

```text
ON_PRE_KEY_EVENT:
KeyEventToNetPacket()
fd
handlerId
```

```text
ON_SUBSCRIBE_KEY:
KeyEventToNetPacket()
fd
subscriberId
```

```text
ON_SUBSCRIBE_KEY_MONITOR:
KeyEventToNetPacket()
status
```

如果扩展数据紧跟 `KeyEventToNetPacket()` 写入，旧客户端会把扩展字段误读成 `fd`、`handlerId`、`subscriberId` 或 `status`，从而破坏旧客户端兼容。

### 8.3 消息级扩展设计

保持 `KeyEventToNetPacket()` 和 `NetPacketToKeyEvent()` 的旧 body 字段顺序稳定。

新增辅助函数：

```cpp
static int32_t WriteKeyEventExt(const std::shared_ptr<KeyEvent> key, NetPacket &pkt);
static int32_t ReadKeyEventExt(NetPacket &pkt, std::shared_ptr<KeyEvent> key);
```

辅助函数使用 UDS/socket 独立的消息级扩展 payload：

```text
rawCode
rawCodeSize
keyItemRawCode...
repeatCount
```

该 payload 不使用 `extFlags`。读取端通过 `NetPacket::UnreadSize()` 判断是否存在消息尾部扩展；如果存在，则按固定顺序读取上述字段。

扩展字段写在完整消息的末尾，即所有旧消息字段写完之后。

扩展字段也在完整消息的末尾读取，即所有旧消息字段读完之后。

### 8.4 消息修改点

以下服务端发送路径需要在所有旧消息字段写完后追加 `WriteKeyEventExt()`。

| 路径 | 旧后缀字段 | 扩展字段位置 |
| --- | --- | --- |
| `EventDispatchHandler::DispatchKeyEventPid()` | `fd`、security enhance data | 旧后缀之后 |
| `EventPreMonitorHandler::SessionHandler::SendToClient()` | `fd`、`handlerId` | 旧后缀之后 |
| `EventMonitorHandler::SessionHandler::SendToClient(KeyEvent)` | 无 | legacy key-event body 之后 |
| `KeySubscriberHandler::NotifySubscriber()` | `fd`、`subscriberId` | 旧后缀之后 |
| `KeyMonitorManager::NotifyKeyMonitor()` | `status` | 旧后缀之后 |
| `InputActiveSubscriberHandler::NotifySubscriber()` | `subscriberId` | 旧后缀之后 |
| `EventInterceptorHandler::SessionHandler::SendToClient(KeyEvent)` | 前缀 `handlerType`、`deviceTags`；无后缀 | legacy key-event body 之后 |
| `KeyEventHookManager::HookHandler()` | 无 | legacy key-event body 之后 |
| `KeyEventHook::OnKeyEvent()` 或相关 hook 发送路径 | 现有旧字段 | 旧字段之后 |

对应客户端 handler 需要在读取完旧字段后调用 `ReadKeyEventExt()`。

| 客户端 handler | 读取扩展字段位置 |
| --- | --- |
| `ClientMsgHandler::OnKeyEvent()` | `fd` 和 security enhance data 之后 |
| `ClientMsgHandler::OnPreKeyEvent()` | `fd`、`handlerId` 之后 |
| `ClientMsgHandler::OnKeyMonitor()` | 旧 monitor 字段之后 |
| `ClientMsgHandler::OnSubscribeKeyEventCallback()` | 旧 subscriber 字段之后 |
| `ClientMsgHandler::OnSubscribeKeyMonitor()` | 旧 monitor 字段之后 |
| `ClientMsgHandler::OnSubscribeInputActiveCallback()` | 旧 input-active 字段之后 |
| `ClientMsgHandler::ReportKeyEvent()` | 旧 report 字段之后 |
| `ClientMsgHandler::OnHookKeyEvent()` / `OnHookKey()` | 旧 hook 字段之后 |

### 8.5 UDS 兼容性

| 服务端 | 客户端 | 结果 |
| --- | --- | --- |
| 旧版本 | 新版本 | 无扩展尾部，新增字段使用默认值；扩展读取直接返回成功，不打印错误日志 |
| 新版本 | 旧版本 | 旧客户端正确读取旧字段并忽略消息尾部 |
| 新版本 | 新版本 | 扩展字段正常恢复 |

`ReadKeyEventExt()` 对缺少扩展数据直接返回成功，不打印错误日志；`rawCode`、`KeyItem::rawCode` 和 `repeatCount` 保持默认值。

`rawCode` 和 `repeatCount` 是附加观测字段，不是主事件分发必需字段。因此 `WriteKeyEventExt()` 和 `ReadKeyEventExt()` 可以通过返回值表达扩展读写是否成功，但调用点只能根据返回值打印错误日志，不能因为扩展读写失败而中断主事件分发、monitor、subscriber、interceptor 或 hook 主流程。

现有 `NetPacket` 继承自 `StreamBuffer`，可通过 `UnreadSize()` 安全查询剩余可读字节。`ReadKeyEventExt()` 必须先检查 `UnreadSize()`，不能通过盲读判断扩展是否存在。盲读越界会设置 `READ_ERROR`，导致 `ChkRWError()` 变为 true，后续读取不可恢复。

同理，`WriteKeyEventExt()` 在写扩展字段前必须通过 `GetAvailableBufSize()` 预检查剩余可写空间。扩展空间不足时直接返回 `RET_ERR`，由调用点打印错误日志；不能先盲写再忽略错误，因为 `StreamBuffer` 一旦进入 `WRITE_ERROR` 状态，后续发送路径里的 `ChkRWError()` 会把扩展失败升级为主流程失败。

推荐读取规则：

```text
UnreadSize() == 0:
    旧消息，无扩展，直接返回成功
UnreadSize() > 0 且不足最小扩展长度:
    扩展截断，打印错误日志后返回
UnreadSize() >= 最小扩展长度:
    按 rawCode、rawCodeSize、keyItemRawCode...、repeatCount 固定顺序读取
```

## 9. 校验与错误处理

### 9.1 rawCode 校验

`rawCode` 可以为 `-1` 或非负值。

反序列化时不应拒绝 `-1`。

### 9.2 repeatCount 校验

`repeatCount` 保存值必须为非负值。

如果反序列化读取到负值：

```text
repeatCount = 0
```

### 9.3 数组大小校验

对于 raw-code item 数组：

```text
0 <= rawCodeSize <= keys_.size()
rawCodeSize <= maxKeysSize
```

读取固定长度数据前必须检查剩余可读字节。

## 10. ABI 与部署风险

给 `KeyEvent` 和 `KeyItem` 新增成员会改变 C++ 对象布局。

风险：

- 只替换一个或几个 `.so` 会造成新旧对象布局混用。
- 布局混用可能导致内存破坏或系统 panic。

验证要求：

- 使用一致的完整构建版本，或确保替换的是完整 ABI 一致的库集合。
- 不能把部分 `.so` 替换作为该修改的唯一验证方式。

序列化兼容只能解决 IPC 和 socket 数据兼容问题，不能解决混合二进制之间的类布局兼容问题。

## 11. 测试计划

### 11.1 KeyEvent 单元测试

测试用例：

- 默认 `KeyEvent::GetRawCode() == -1`。
- 默认 `KeyItem::GetRawCode() == -1`。
- 默认 `KeyEvent::GetRepeatCount() == 0`。
- `SetRawCode()` 和 `GetRawCode()` 往返一致。
- `SetRepeatCount()` 和 `GetRepeatCount()` 往返一致。
- 负数 `repeatCount` 归一化为 `0`。
- copy 构造保留 `rawCode`、key-item `rawCode` 和 `repeatCount`。
- `Reset()` 恢复 `rawCode == -1`、`repeatCount == 0`。

### 11.2 Parcel 测试

测试用例：

- 新结构体 parcel 往返恢复：
  - event `rawCode`，
  - key-item `rawCode`，
  - `repeatCount`。
- `WriteToParcel()` 和 `ReadFromParcel()` 字段顺序一致。
- `rawCodeSize` 与 key item 数量一致。
- 非法 raw-code size 读取失败。
- 截断结构体字段读取失败。

### 11.3 KeyAutoRepeat 测试

测试用例：

- 初始 key down 保持 `repeatCount == 0`。
- 第一次生成重复键事件 `repeatCount == 1`。
- 第二次生成重复键事件 `repeatCount == 2`。
- key up 后重置内部重复计数。
- key cancel 后重置内部重复计数。
- 切换 key code 后重置内部重复计数。
- A 按住重复后按下 B，A 的重复停止，B 的 `repeatCount` 从 `0` 重新开始，并在 B 的重复事件中按 `1`、`2` 递增。
- 现有 `IsRepeat()` 和 `IsRepeatKey()` 行为不变。

### 11.4 UDS/socket 序列化测试

测试用例：

- legacy `KeyEventToNetPacket()` body 仍可被现有客户端 handler 读取。
- 消息级扩展可恢复 event `rawCode`、key-item `rawCode` 和 `repeatCount`。
- 新客户端读取无扩展旧消息时，扩展读取直接返回成功并继续使用默认值。
- 新客户端读取畸形扩展尾部时，扩展读取返回错误码，调用点只打印日志并继续主流程：
  - 剩余字节大于 `0` 但小于最小扩展长度。
  - `keyItemRawCodeCount < 0`。
  - `keyItemRawCodeCount > keys.size()`。
  - `keyItemRawCodeCount` 合法但剩余字节不足以读取 key-item rawCode 和 `repeatCount`。
- 新服务端消息中，旧后缀字段必须在扩展前仍可正确读取：
  - `fd`
  - `handlerId`
  - `subscriberId`
  - `status`
  - security enhance data
- 截断扩展数据不能破坏旧字段读取。

### 11.5 回归测试

测试用例：

- `KeySubscriberHandler::IsRepeatedKeyEvent()` 结果不变。
- `InputWindowsManager` 基于 `IsRepeatKey()` 的焦点行为不变。
- `PackageKeyUpEvent()` 需要使用入参 `rawCode` 给补偿 `KEY_ACTION_UP` 事件和 key item 赋值。
- hook、monitor、pre-monitor、subscriber、interceptor 和普通 dispatch 链路仍能正常收到 key event。

## 12. 实现顺序建议

推荐实现顺序：

1. 新增 `rawCode`、`repeatCount` 数据成员和访问接口。
2. 在 `KeyEventNormalize::Normalize()` 中赋值 `rawCode`。
3. 在 `KeyAutoRepeat` 中赋值 `repeatCount`。
4. 按 SE 结构体方式更新 `Parcel` 字段序列化。
5. 增加 UDS/socket 消息级扩展辅助函数。
6. 更新所有 key-event 消息发送和接收路径，在消息尾部写入和读取扩展。
7. 补充单元测试和兼容测试。
8. 使用一致的完整构建版本执行格式检查、构建和板侧验证。

## 13. 设计结论

本次实现采用以下结论：

- `KEY_ACTION_UP` 和 `KEY_ACTION_CANCEL` 上的 `repeatCount` 保持 `0`，不携带最终重复次数。
- 客户端是否需要消费 `rawCode` 和 `repeatCount`。如果需要，需要另行设计 SDK/API 暴露方案。
