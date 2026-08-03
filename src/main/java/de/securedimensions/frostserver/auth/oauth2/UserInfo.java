/*
 * Copyright (C) 2023 Secure Dimensions GmbH, D-81377
 * Munich, Germany.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package de.securedimensions.frostserver.auth.oauth2;

import de.fraunhofer.iosb.ilt.settings.Settings;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.IntNode;
import tools.jackson.databind.node.NullNode;

public class UserInfo {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserInfo.class);

    private final ConcurrentHashMap<ExpiringKey<String>, JsonNode> introspectionCache;
    private final String clientId;
    private final String clientSecret;
    private final String scope;
    private final long expires;
    private String userinfoUrl;

    private ScheduledExecutorService executor;

    UserInfo(Settings authSettings) {
        userinfoUrl = authSettings.get("oauth.userinfoUrl");
        scope = authSettings.get("oauth.scope", "openid");
        clientId = authSettings.get("oauth.clientId");
        clientSecret = authSettings.get("oauth.clientSecret");
        expires = authSettings.getLong("oauth.cacheExpires", 60);

        introspectionCache = new ConcurrentHashMap<>(10);
        executor = Executors.newScheduledThreadPool(1);
        LOGGER.debug("starting executor for UserInfo");
        executor.scheduleAtFixedRate(new ExpiredKeyRemover(introspectionCache), 30, 10, TimeUnit.SECONDS);
    }

    public void shutdown() {
        LOGGER.debug("shutting down executor for UserInfo");
        executor.shutdownNow();
    }

    public JsonNode getUserInfo(String token) {
        LOGGER.debug("getUserInfo()");
        if (!introspectionCache.containsKey(new ExpiringKey(token))) {
            LOGGER.debug("requesting user info");
            JsonNode userinfoResponse = getUserInfoResponse(token);
            if (userinfoResponse.has("error")) {
                LOGGER.debug("userinfo response invalid for token: {}".formatted(token));
                return userinfoResponse;
            } else {
                LOGGER.debug("adding userinfo to Cache: {}".formatted(token));
                long ttl = expires;
                if (userinfoResponse.has("exp")) {
                    long now = System.currentTimeMillis() / 1000;
                    long remaining = userinfoResponse.get("exp").asLong() - now;
                    ttl = (remaining < expires) ? Math.abs(remaining) : expires;
                }

                introspectionCache.put(new ExpiringKey(token, ttl * 1000), userinfoResponse);
            }

        }
        LOGGER.debug("returning user info from Cache: {}".formatted(token));
        return introspectionCache.get(new ExpiringKey(token));
    }

    private JsonNode getUserInfoResponse(String token) {
        LOGGER.debug("fetching UserInfo for token: {}".formatted(token));
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            final HttpPost httpPost = new HttpPost(userinfoUrl);
            final List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair("client_id", clientId));
            params.add(new BasicNameValuePair("client_secret", clientSecret));
            params.add(new BasicNameValuePair("scope", scope));
            httpPost.setEntity(new UrlEncodedFormEntity(params));
            httpPost.addHeader("accept", "application/json");
            httpPost.setHeader("Authorization", "Bearer " + token);

            ResponseHandler<JsonNode> responseHandler = httpResponse -> {
                final int statusCode = httpResponse.getStatusLine().getStatusCode();
                if (statusCode != HttpStatus.SC_OK) {
                    return IntNode.valueOf(statusCode);
                }
                final HttpEntity entity = httpResponse.getEntity();
                BufferedReader reader = new BufferedReader(new InputStreamReader(entity.getContent(), Charset.defaultCharset()));
                ObjectMapper mapper = new ObjectMapper();
                return mapper.readTree(reader);

            };
            return client.execute(httpPost, responseHandler);
        } catch (IOException ex) {
            return NullNode.getInstance();
        }

    }
}
