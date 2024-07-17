/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

  /**
   * Set the number of touchpad scrolling rows.
   *
   * @param { number } rows - Indicates the number of touchpad scrolling rows.
   * @param { AsyncCallback<void> } callback - Callback used to return the result.
   * @throws { BusinessError } 202 - SystemAPI permission error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.Pointer
   * @systemapi hide for inner use.
   * @since 12
   */
  function setTouchpadScrollRows(rows: number, callback: AsyncCallback<void>): void;

  /**
   * Set the number of touchpad scrolling rows.
   *
   * @param { number } rows - Indicates the number of touchpad scrolling rows.
   * @returns { Promise<void> } Returns the result through a promise.
   * @throws { BusinessError } 202 - SystemAPI permission error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.Pointer
   * @systemapi hide for inner use.
   * @since 12
   */
  function setTouchpadScrollRows(rows: number): Promise<void>;

  /**
   * Get the number of touchpad scrolling rows.
   *
   * @param { AsyncCallback<number> } callback - Callback used to return the result.
   * @throws { BusinessError } 202 - SystemAPI permission error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.Pointer
   * @systemapi hide for inner use.
   * @since 12
   */
  function getTouchpadScrollRows(callback: AsyncCallback<number>): void;

  /**
   * Get the number of touchpad scrolling rows.
   *
   * @returns { Promise<number> } Returns the result through a promise.
   * @throws { BusinessError } 202 - SystemAPI permission error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.Pointer
   * @systemapi hide for inner use.
   * @since 12
   */
  function getTouchpadScrollRows(): Promise<number>;

  /**
   * Set touchpad three finger switch state.
   *
   * @param { boolean } state - Indicates whether the touchpad three finger switch is enabled.
   * <br>true: user can use three finger function. otherwise can't use.
   * @param { AsyncCallback<void> } callback - Callback used to return the result.
   * @throws { BusinessError } 202 - SystemAPI permission error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.Pointer
   * @systemapi hide for inner use.
   * @since 12
   */
  function setTouchpadThreeFingersTapSwitch(state: boolean, callback: AsyncCallback<void>): void;

  /**
   * Set touchpad three finger switch state.
   *
   * @param { boolean } state - Indicates whether the touchpad three finger switch is enabled.
   * <br>true: user can use three finger function. otherwise can't use.
   * @returns { Promise<void> } Returns the result through a promise.
   * @throws { BusinessError } 202 - SystemAPI permission error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.Pointer
   * @systemapi hide for inner use.
   * @since 12
   */
  function setTouchpadThreeFingersTapSwitch(state: boolean): Promise<void>;

  /**
   * Get touchpad three finger switch state.
   *
   * @param { AsyncCallback<boolean> } callback - Callback used to return the result.
   * @throws { BusinessError } 202 - SystemAPI permission error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.Pointer
   * @systemapi hide for inner use.
   * @since 12
   */
  function getTouchpadThreeFingersTapSwitch(callback: AsyncCallback<boolean>): void;

  /**
   * Get touchpad three finger switch state.
   *
   * @returns { Promise<boolean> } Returns the result through a promise.
   * @throws { BusinessError } 202 - SystemAPI permission error.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;
   * <br>2. Incorrect parameter types; 3. Parameter verification failed.
   * @syscap SystemCapability.MultimodalInput.Input.Pointer
   * @systemapi hide for inner use.
   * @since 12
   */
  function getTouchpadThreeFingersTapSwitch(): Promise<boolean>;