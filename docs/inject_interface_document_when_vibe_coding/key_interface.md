【需求价值】:  满足生态应用使用TS接口模拟用户操作的诉求
【需求场景】：自动化工具录制用户输入操作回放功能
【需求描述】:  

背景：应用名称LiveRPA Studio,桌面自动化工具，要做一个录制键鼠操作 再回放的功能，诉求通过TS接口将用户的操作回放出来操作设备。

输入：业务方注入按键（按下/抬起）输入事件
处理：a) 正常场景（有权限的业务方）: 按键输入事件对照用户正式操作按键设备的规则分发到各业务方，并记录用户使用该权限
           b) 异常场景1 (注入事件不符合用户操作序列）：无按下直接注入抬起，向业务方反馈失败
           c) 异常场景2 (无权限的业务方）：向业务方反馈错误
输出：按键输入事件被分发到业务方

注1：capslock、numLock、scrollLock按键注入事件会影响对应的led的状态
注2：注入的按键按下事件仅影响修饰键(ctrl/shift/alt/meta)状态和三个灯的状态，修饰键区分左右

【验收场景和标准】：
1. 通过接口注入单键按下&抬起事件，与用户同按键按下&抬起效果相同（除却用户操作和注入操作被区分的场景）
2. 通过接口注入组合键按下&抬起事件，与用户同按键按下&抬起效果相同（除却用户操作和注入操作被区分的场景）

【涉及xxxKIT】：Input Kit
【是否影响应用兼容性】: 否
【外部依赖】: 不涉及
【性能功耗指标】: NA
【验收平台】：PC
【1+8设备差异规格】：
PC：接口可用
其他产品形态：调用接口必然失败，失败原因是无权限
【涉及全局特性】：不涉及

# Key Interface
```ts
/**
   * Object used to simulate key input events. This object can be used to simulate key operations. 
   * The simulated key operation sequence must meet the following requirements:
   * 1. You can only lift it by pressing it first
   * 2. Only the last button that is pressed and not lifted can be pressed repeatedly.
   * 3. A maximum of five keys are not lifted after being pressed.
   *
   * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  interface KeyboardController {  
    /**
     * Simulates the press of a specified key.
     *
     * @permission ohos.permission.CONTROL_DEVICE
     * @param { KeyCode } keyCode - Key code
     * @returns { Promise<void> } Returns the result through a promise.
     * @throws { BusinessError } 201 - Permission verification failed.
     *     The application does not have the permission required to call the API
     * @throws { BusinessError } 4300001 - Key pressed but not last pressed key.
     * @throws { BusinessError } 3800001 - Input service exception.
     * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
     * @stagemodelonly
     * @since 26.0.0 dynamic&static
     */
    pressKey(keyCode: KeyCode): Promise<void>;
    /**
     * Releasing the specified key
     *
     * @permission ohos.permission.CONTROL_DEVICE
     * @param { KeyCode } keyCode - Key code
     * @returns { Promise<void> } Returns the result through a promise.
     * @throws { BusinessError } 201 - Permission verification failed.
     *     The application does not have the permission required to call the API
     * @throws { BusinessError } 4300001 - The key is not pressed.
     * @throws { BusinessError } 3800001 - Input service exception.
     * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
     * @stagemodelonly
     * @since 26.0.0 dynamic&static
     */
    releaseKey(keyCode: KeyCode): Promise<void>;
  }
  /**
   * Obtains a keyboard controller, through which keyboard operations can be simulated.
   *
   * @permission ohos.permission.CONTROL_DEVICE
   * @returns { Promise<KeyboardController> } Promise used to returns the result.
   * @throws { BusinessError } 201 - Permission verification failed.
   *     The application does not have the permission required to call the API
   * @throws { BusinessError } 801 - Capability not supported.
   * @throws { BusinessError } 3800001 - Input service exception.
   * @syscap SystemCapability.MultimodalInput.Input.InputSimulator
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  function createKeyboardController(): Promise<KeyboardController>;
```