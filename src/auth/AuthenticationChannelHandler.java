package net.opentsdb.auth;
// This file is part of OpenTSDB.
// Copyright (C) 2010-2012  The OpenTSDB Authors.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 2.1 of the License, or (at your
// option) any later version.  This program is distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
// General Public License for more details.  You should have received a copy
// of the GNU Lesser General Public License along with this program.  If not,
// see <http://www.gnu.org/licenses/>.

import net.opentsdb.core.TSDB;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

/**
 * @since 2.3
 */
public class AuthenticationChannelHandler extends SimpleChannelUpstreamHandler {
  private static final Logger LOG = LoggerFactory.getLogger(AuthenticationChannelHandler.class);
  private TSDB tsdb = null;
  private AuthenticationPlugin authentication = null;

  public AuthenticationChannelHandler(TSDB tsdb) {
    LOG.info("Setting up AuthenticationChannelHandler");
    this.authentication = tsdb.getAuth();
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) {
    e.getCause().printStackTrace();
    e.getChannel().close();
  }

  @Override
  public void messageReceived(ChannelHandlerContext ctx, MessageEvent authEvent) {
    LoginContext lc = null;
    String loginModule = tsdb.getConfig().getString("tsd.core.auth.login_module");

    try {
      EmbeddedCallbackHandler ec = new EmbeddedCallbackHandler(authEvent);
      lc = new LoginContext(loginModule, ec);
    } catch (LoginException le) {
      LOG.error("Error during Login Context Setup: " + le);
      return;
    }

    try {
      lc.login();
      ctx.getPipeline().remove(this);
    } catch (Exception e) {
      LOG.error("Authentication Failed: " + e);
      return;
    }
    LOG.info("Authentication Completed");
  }
}
