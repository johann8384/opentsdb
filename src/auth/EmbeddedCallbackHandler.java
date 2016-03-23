package net.opentsdb.auth;
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

import com.sun.javaws.exceptions.InvalidArgumentException;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.*;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

public class EmbeddedCallbackHandler implements CallbackHandler {
  private String[] authCommand;
  private String authType;
  private String accessKey;
  private String accessSecretKey;
  private String digestHash;
  private Map<String, String> fields;
  private static final Logger LOG = LoggerFactory.getLogger(EmbeddedCallbackHandler.class);
    public EmbeddedCallbackHandler(MessageEvent authEvent) {
      String authResponse = "AUTH_FAIL\r\n";
      try {
        final Object authCommand = authEvent.getMessage();
        if (authCommand instanceof String[]) {
          handleTelnetAuth((String[]) authCommand);
        } else if (authCommand instanceof HttpRequest) {
          handleHTTPAuth((HttpRequest) authCommand);
        } else {
          LOG.error("Unexpected message type "
                + authCommand.getClass() + ": " + authCommand);
        }
      } catch (Exception e) {
        LOG.error("Unexpected exception caught while serving: " + e);
      }
  }

  private void handleTelnetAuth(String[] command) {
    if (command.length  < 3 || command.length > 4) {
      LOG.error("Invalid Authentication Command Length: " + Integer.toString(command.length));
    } else if (command[0].equals("auth")) {
      this.authCommand = command;
      if (command[1].trim().toLowerCase().equals("basic")) {
        // Command should be 'auth basic accessKey accessSecretKey'
        this.authType = "basic";
        this.accessKey = command[2];
        this.accessSecretKey = command[3];
      } else {
        // Command should be 'auth hmacsha256 accessKey:digest:epoch:nonce'
        this.authType = command[1].trim().toLowerCase();
        this.digestHash = command[2];
        this.fields = AuthenticationUtil.stringToMap(command[2], ":");
        this.accessKey = fields.get("accessKey");
        this.accessSecretKey = null;
      }
    } else {
      LOG.error("Command is not auth: " + command[0]);
    }
  }

  //Authorization: OpenTSDB accessKey:digest:epoch:nonce
  private void handleHTTPAuth(final HttpRequest req) {
    Iterable<Map.Entry<String,String>> headers = req.headers();
    Iterator entries = headers.iterator();
    while (entries.hasNext()) {
      Map.Entry thisEntry = (Map.Entry) entries.next();
      String key = (String) thisEntry.getKey();
      String value = (String) thisEntry.getValue();
      if (key.trim().toLowerCase().equals("authorization")) {
        String[] fieldsRaw = value.split(" ");
        if (fieldsRaw.length == 2 && fieldsRaw[0].trim().toLowerCase().equals("opentsdb")) {
          this.authCommand = fieldsRaw[1].trim().toLowerCase().split(":");
          this.digestHash = fieldsRaw[1];
          this.fields = AuthenticationUtil.stringToMap(fieldsRaw[1], ":");
          this.authType = "http";
          this.accessKey = fields.get("accessKey");
          this.accessSecretKey = null;
        } else {
          throw new IllegalArgumentException("Improperly formatted Authorization Header: " + value);
        }
      }
    }
    LOG.info("No Authorization Header Found");
  }

  /**
   * Invoke an array of Callbacks.
   *
   *
   * @param callbacks an array of Callback objects which contain
   *          the information requested by an underlying security
   *          service to be retrieved or displayed.
   *
   * @exception java.io.IOException if an input or output error occurs.
   *
   * @exception UnsupportedCallbackException if the implementation of this
   *          method does not support one or more of the Callbacks
   *          specified in the callbacks parameter.
   */
  public void handle(Callback[] callbacks)
          throws IOException, UnsupportedCallbackException {

    for (int i = 0; i < callbacks.length; i++) {
      if (callbacks[i] instanceof NameCallback) {
        NameCallback nc = (NameCallback)callbacks[i];
        nc.setName(this.accessKey);
      } else if (callbacks[i] instanceof PasswordCallback) {
        PasswordCallback pc = (PasswordCallback) callbacks[i];
        if (this.authType.equals("basic")) {
          pc.setPassword(this.accessSecretKey.toCharArray());
        } else {
          pc.setPassword(this.digestHash.toCharArray());
        }
      } else if (callbacks[i] instanceof TextInputCallback) {
        TextInputCallback ti = (TextInputCallback)callbacks[i];
        String prompt = ti.getPrompt();
        if (prompt.equalsIgnoreCase("authType")) {
          ti.setText(this.authType);
        } else if (this.fields.containsKey(prompt)) {
          ti.setText(this.fields.get(prompt));
        } else {
          throw new IOException("Requested key does not exist in fields: " + prompt);
        }
      } else {
        throw new UnsupportedCallbackException
                (callbacks[i], "Unrecognized Callback");
      }
    }
  }
}
