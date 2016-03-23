package net.opentsdb.auth.plugins;
/**
 * Copyright 2015 The opentsdb Authors
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Map;

public class EmbeddedLoginModule implements LoginModule {
  private static final Logger LOG = LoggerFactory.getLogger(EmbeddedLoginModule.class);

  // initial state
  private Subject subject;
  private CallbackHandler callbackHandler;
  private Map sharedState;
  private Map options;

  // configurable option
  private String adminAccessKey;
  private String adminSecretKey;

  // the authentication status
  private boolean succeeded = false;
  private boolean commitSucceeded = false;

  // user name and password
  private String accessKey;
  private char[] accessSecretKey;

  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
    this.subject = subject;
    this.callbackHandler = callbackHandler;
    this.sharedState = sharedState;
    this.options = options;
    this.adminAccessKey = (String)options.get("adminAccessKey");
    this.adminSecretKey = (String)options.get("adminSecretKey");
  }

  @Override
  public boolean login() throws LoginException {
    // prompt for a user name and password
    if (callbackHandler == null)
      throw new LoginException("Error: no CallbackHandler available " +
              "to garner authentication information from the user");

    Callback[] callbacks = new Callback[2];
    callbacks[0] = new NameCallback("\n\naccessKey: ");
    callbacks[1] = new PasswordCallback("accessSecretKey: ", false);

    try {
      callbackHandler.handle(callbacks);
      this.accessKey = ((NameCallback)callbacks[0]).getName();
      char[] tmpPassword = ((PasswordCallback)callbacks[1]).getPassword();
      if (tmpPassword == null) {
        // treat a NULL password as an empty password
        tmpPassword = new char[0];
      }
      this.accessSecretKey = new char[tmpPassword.length];
      System.arraycopy(tmpPassword, 0,
              this.accessSecretKey, 0, tmpPassword.length);
      ((PasswordCallback)callbacks[1]).clearPassword();
    } catch (java.io.IOException ioe) {
      throw new LoginException(ioe.toString());
    } catch (UnsupportedCallbackException uce) {
      throw new LoginException("Error: " + uce.getCallback().toString() +
              " not available to garner authentication information " +
              "from the user");
    }

    char[] desiredSecret = this.adminSecretKey.toCharArray();
    if (desiredSecret.length != this.accessSecretKey.length) {
      LOG.debug("desiredSecret and accessSecretKey are different lengths");
      succeeded = false;
      throw new FailedLoginException("Password Incorrect");
    }
    for (Integer i=0;i<desiredSecret.length;i++) {
      if (desiredSecret[i] != this.accessSecretKey[i]) {
        LOG.debug("accessSecretKey is not correct");
        succeeded = false;
        throw new FailedLoginException("Password Incorrect");
      }
    }
    succeeded = true;
    return true;
  }

  @Override
  public boolean commit() throws LoginException {
    return false;
  }

  @Override
  public boolean abort() throws LoginException {
    return false;
  }

  @Override
  public boolean logout() throws LoginException {
    return false;
  }
}
