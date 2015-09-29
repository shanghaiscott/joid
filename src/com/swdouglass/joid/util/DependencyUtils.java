/*
 * MODIFICATIONS to the original source have been made by
 * Scott Douglass <scott@swdouglass.com>
 *
 * Copyright 2009 Scott Douglass <scott@swdouglass.com>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * The original copyright notice and license terms are below.
 */
package com.swdouglass.joid.util;

/**
 * 
 */
public class DependencyUtils {

  /**
   * This method will create a new instance of the class specified by className.
   *
   * @param className
   * @return
   */
  public static Object newInstance(String className) {
    try {
      return Class.forName(className).newInstance();
    } catch (ClassNotFoundException e) {
      throw new IllegalArgumentException("Not found " + className);
    } catch (IllegalAccessException e) {
      throw new IllegalArgumentException("No access to " + className);
    } catch (InstantiationException e) {
      throw new IllegalArgumentException("Cannot instantiate " + className);
    }
  }
}
