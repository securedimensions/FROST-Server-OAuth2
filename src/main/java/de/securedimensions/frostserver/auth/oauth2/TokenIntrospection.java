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
import java.util.Base64;
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

public class TokenIntrospection {
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenIntrospection.class);

    private final ConcurrentHashMap<ExpiringKey<String>, JsonNode> introspectionCache;
    private final String clientId;
    private final String clientSecret;
    private final String scope;
    private final long expires;
    private String introspectionUrl;

    private ScheduledExecutorService executor;

    TokenIntrospection(Settings authSettings) {
        introspectionUrl = authSettings.get("oauth.introspectionUrl");
        scope = authSettings.get("oauth.scope", "openid");
        clientId = authSettings.get("oauth.clientId");
        clientSecret = authSettings.get("oauth.clientSecret");
        expires = authSettings.getLong("oauth.cacheExpires", 60);

        introspectionCache = new ConcurrentHashMap<>(10);
        executor = Executors.newScheduledThreadPool(1);
        LOGGER.debug("starting executor for TokenIntrospection");
        executor.scheduleAtFixedRate(new ExpiredKeyRemover(introspectionCache), 30, 10, TimeUnit.SECONDS);
    }

    public void shutdown() {
        LOGGER.debug("shutting down executor for TokenIntrospection");
        executor.shutdownNow();
    }

    public JsonNode getTokenInfo(String token) {
        LOGGER.debug("getTokenInfo()");
        if (!introspectionCache.containsKey(new ExpiringKey(token))) {
            LOGGER.debug("requesting token info");
            JsonNode introspectionResponse = getIntrospectionResponse(token, scope);
            if (introspectionResponse.has("active") && introspectionResponse.get("active").asBoolean()) {
                LOGGER.debug("adding token to Cache: {}".formatted(token));
                long ttl = expires;
                if (introspectionResponse.has("exp")) {
                    long now = System.currentTimeMillis() / 1000;
                    long remaining = introspectionResponse.get("exp").asLong() - now;
                    ttl = (remaining < expires) ? Math.abs(remaining) : expires;
                }

                introspectionCache.put(new ExpiringKey(token, ttl * 1000), introspectionResponse);
            } else {
                LOGGER.debug("token expired: {}".formatted(token));
                return introspectionResponse;
            }

        }
        LOGGER.debug("returning token from Cache: {}".formatted(token));
        return introspectionCache.get(new ExpiringKey(token));
    }

    private JsonNode getIntrospectionResponse(String token, String scope) {
        LOGGER.debug("fetching TokenInfo for token: {}".formatted(token));
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            final HttpPost httpPost = new HttpPost(introspectionUrl);
            final List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair("token", token));
            params.add(new BasicNameValuePair("scope", scope));
            httpPost.setEntity(new UrlEncodedFormEntity(params));
            httpPost.addHeader("accept", "application/json");
            httpPost.setHeader("Authorization", "BASIC " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()));

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
