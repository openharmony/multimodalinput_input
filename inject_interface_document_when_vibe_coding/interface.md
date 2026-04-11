# 需求描述
【需求价值】:  满足生态应用使用TS接口模拟用户操作的诉求
【需求场景】：自动化工具录制用户输入操作回放功能
【需求描述】:  

背景：要做一个录制键鼠操作 再回放的功能，诉求通过TS接口将用户的操作回放出来操作设备。

输入：业务方注入鼠标及解释为鼠标事件的触控板手势（按钮/滚轮/移动）输入事件，触控板双指轴事件
处理：
  a) 正常场景（有权限的业务方）: 鼠标输入事件对照用户正式操作触屏设备的规则分发到各业务方，并记录用户使用该权限
  b) 异常场景1 (注入事件不符合用户操作序列）：比如无按下直接注入抬起，向业务方反馈失败
  c) 异常场景2 (无权限的业务方）：向业务方反馈错误

输出：按键输入事件被分发到业务方

【验收场景和标准】：
1. 通过接口注入按钮按下&抬起事件，与用户操作物理鼠标上相同按钮的按下&抬起效果相同（除去用户操作和注入操作被区分的场景）
2. 通过接口注入移动事件，与用户操作物理鼠标移动光标的效果相同（除去用户操作和注入操作被区分的场景）
3. 通过接口注入滚动事件，与用户操作物理鼠标滚轮的效果相同（除去用户操作和注入操作被区分的场景）
4. 通过接口注入双指捏合/滑动事件，与用户操作物理触控板的效果相同（除去用户操作和注入操作被区分的场景），不包含旋转

PC：接口可用
其他产品形态：调用接口必然失败，失败原因是无权限

# 业务场景
最终这个特性需要用于远程控制，实现类似于TeamViewer的功能


# 鼠标注入接口设计

```ts
/**
 * Mouse controller object. This object can be used to simulate mouse operations. 
 * The simulated mouse operation sequence meets the following requirements:
 * 1. The button must be pressed and then lifted.
 * 2. The same button cannot be pressed again if it is not lifted after being pressed.
 * 3. The complete sequence of axis events is start, update, and end.
 * 4. There can only be one unfinished axis event at a time.
 *
 * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
 * @stagemodelonly
 * @since 26.0.0 dynamic&static
 */
interface MouseController {
  
  /**
   * Move the mouse cursor to the specified position.
   *
   * @permission ohos.permission.CONTROL_DEVICE
   * @param { int } displayId - Display ID
   *     The value should be an integer.
   * @param { int } displayX - x-coordinate
   *     The value should be an integer.
   *     <br>Unit:px.
   * @param { int } displayY - y-coordinate
   *     The value should be an integer.
   *     <br>Unit:px.
   * @returns { Promise<void> } Returns the result through a promise.
   * @throws { BusinessError } 201 - Permission verification failed.
   *     The application does not have the permission required to call the API
   * @throws { BusinessError } 4300002 - The display does not exist.
   * @throws { BusinessError } 3800001 - input service exception
   * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  moveTo(displayId: int, displayX: int, displayY: int): Promise<void>;
  
  /**
   * Press mouse button down
   *
   * @permission ohos.permission.CONTROL_DEVICE
   * @param { Button } button - Mouse button
   * @returns { Promise<void> } Returns the result through a promise.
   * @throws { BusinessError } 201 - Permission verification failed.
   *     The application does not have the permission required to call the API
   * @throws { BusinessError } 4300001 - Button pressed.
   * @throws { BusinessError } 3800001 - input service exception
   * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  pressButton(button: Button): Promise<void>;
  
  /**
   * Release mouse button up
   *
   * @permission ohos.permission.CONTROL_DEVICE
   * @param { Button } button - Mouse button
   * @returns { Promise<void> } Returns the result through a promise.
   * @throws { BusinessError } 201 - Permission verification failed.
   *     The application does not have the permission required to call the API
   * @throws { BusinessError } 4300001 - Button not pressed
   * @throws { BusinessError } 3800001 - input service exception
   * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  releaseButton(button: Button): Promise<void>;
  
  /**
   * Begin axis event
   *
   * @permission ohos.permission.CONTROL_DEVICE
   * @param { Axis } axis - Axis type
   * @param { int } value - Axis value
   *     The value should be an interager.
   * @returns { Promise<void> } Returns the result through a promise.
   * @throws { BusinessError } 201 - Permission verification failed.
   *     The application does not have the permission required to call the API
   * @throws { BusinessError } 4300001 - Axis event in progress.
   * @throws { BusinessError } 3800001 - input service exception
   * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  beginAxis(axis: Axis, value: int): Promise<void>;
  
  /**
   * Update axis event
   *
   * @permission ohos.permission.CONTROL_DEVICE
   * @param { Axis } axis - Axis type
   * @param { int } value - Axis value
   *     The value should be an interager.
   * @returns { Promise<void> } Returns the result through a promise.
   * @throws { BusinessError } 201 - Permission verification failed.
   *     The application does not have the permission required to call the API
   * @throws { BusinessError } 4300001 - Must be started but not finished
   * @throws { BusinessError } 3800001 - input service exception
   * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  updateAxis(axis: Axis, value: int): Promise<void>;
  
  /**
   * End axis event
   *
   * @permission ohos.permission.CONTROL_DEVICE
   * @param { Axis } axis - Axis type
   * @returns { Promise<void> } Returns the result through a promise.
   * @throws { BusinessError } 201 - Permission verification failed.
   *     The application does not have the permission required to call the API
   * @throws { BusinessError } 4300001 - The axis not began.
   * @throws { BusinessError } 3800001 - input service exception
   * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  endAxis(axis: Axis): Promise<void>;
}

/**
 * Get mouse controller
 *
 * @permission ohos.permission.CONTROL_DEVICE
 * @returns { Promise<MouseController> } Returns the result through a promise.
 * @throws { BusinessError } 201 - Permission verification failed.
 *     The application does not have the permission required to call the API
 * @throws { BusinessError } 801 - Capability not supported.
 * @throws { BusinessError } 3800001 - Input service exception.
 * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
 * @stagemodelonly
 * @since 26.0.0 dynamic&static
 */
function getMouseController(): Promise<MouseController>;

```

# 设计约束
> 1. MouseController 应该维护在客户端
> 2. MouseCOntroller 的数量不做限制
> 3. 不必要为每个TS接口都实现一个从Proxy->IPC->Stub-Service 的全流程实现，在客户端将每个接口的语义转换为一个对应的PointerEvent事件，直接向服务端注入这个PointerEvent事件即可，
> 4. 服务端不感知MouseController的概念