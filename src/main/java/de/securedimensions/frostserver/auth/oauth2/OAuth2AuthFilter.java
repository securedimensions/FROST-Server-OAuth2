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

import static de.fraunhofer.iosb.ilt.frostserver.settings.CoreSettings.*;
import static de.securedimensions.frostserver.auth.oauth2.OAuth2AuthProvider.*;

import de.fraunhofer.iosb.ilt.frostserver.settings.ConfigUtils;
import de.fraunhofer.iosb.ilt.frostserver.settings.CoreSettings;
import de.fraunhofer.iosb.ilt.frostserver.util.HttpMethod;
import de.fraunhofer.iosb.ilt.frostserver.util.user.PrincipalExtended;
import de.fraunhofer.iosb.ilt.settings.ConfigDefaults;
import de.fraunhofer.iosb.ilt.settings.Settings;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.IntNode;

/**
 * A Tomcat filter for OAuth2 Authentication.
 */
public class OAuth2AuthFilter implements Filter {

    /**
     * The logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2AuthFilter.class);

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String AUTHORIZATION_REQUIRED_HEADER = "WWW-Authenticate";
    private static final String AUTH_SCHEME = "Bearer";
    private static final UserData USER_DATA_NO_USER = new UserData("anonymous", null, Collections.emptySet());
    private final Map<HttpMethod, AuthChecker> methodCheckers = new EnumMap<>(HttpMethod.class);
    private boolean allowAnonymous;
    private boolean authenticateOnly;
    private boolean registerUserLocally;
    private DatabaseHandler databaseHandler;

    private String authHeaderValue;
    private String adminUid;
    private TokenIntrospection tokenIntrospection;
    private UserInfo userInfo;

    private static String getInitParamWithDefault(FilterConfig filterConfig, String paramName, Class<? extends ConfigDefaults> defaultsProvider) {
        return getInitParamWithDefault(filterConfig, paramName, ConfigUtils.getDefaultValue(defaultsProvider, paramName));
    }

    private static String getInitParamWithDefault(FilterConfig filterConfig, String paramName, String defValue) {
        String value = filterConfig.getInitParameter(paramName);
        if (value == null) {
            LOGGER.info("Filter setting {}, using default value: {}", paramName, defValue);
            return defValue;
        }
        LOGGER.info("Filter setting {}, set to value: {}", paramName, value);
        return value;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        LOGGER.info("Turning on OAuth2 authentication.");
        String roleGet = getInitParamWithDefault(filterConfig, TAG_HTTP_ROLE_GET, OAuth2AuthProvider.class);
        String rolePost = getInitParamWithDefault(filterConfig, TAG_HTTP_ROLE_POST, OAuth2AuthProvider.class);
        String rolePatch = getInitParamWithDefault(filterConfig, TAG_HTTP_ROLE_PATCH, OAuth2AuthProvider.class);
        String rolePut = getInitParamWithDefault(filterConfig, TAG_HTTP_ROLE_PUT, OAuth2AuthProvider.class);
        String roleDelete = getInitParamWithDefault(filterConfig, TAG_HTTP_ROLE_DELETE, OAuth2AuthProvider.class);
        String anonRead = getInitParamWithDefault(filterConfig, TAG_AUTH_ALLOW_ANON_READ, "F");
        String authOnly = getInitParamWithDefault(filterConfig, TAG_AUTHENTICATE_ONLY, "F");

        allowAnonymous = "T".equals(anonRead);
        authenticateOnly = "T".equals(authOnly);

        adminUid = getInitParamWithDefault(filterConfig, TAG_ADMIN_UID, "n/a");

        ServletContext context = filterConfig.getServletContext();
        Object attribute = context.getAttribute(TAG_CORE_SETTINGS);
        if (!(attribute instanceof CoreSettings coreSettings)) {
            throw new IllegalArgumentException("Could not load core settings.");
        }
        Settings authSettings = coreSettings.getAuthSettings();
        // Reuse the TokenIntrospection (and its ExpiredKeyRemover executor)
        // that OAuth2AuthProvider#addFilter published on the ServletContext,
        // if there is one, rather than creating a second instance: only
        // this filter's shutdown() is guaranteed to run (via Filter#destroy(),
        // called reliably by the servlet container), so the Provider's own
        // instance would otherwise leak a background thread past webapp
        // undeploy. Falls back to creating our own for setups that use this
        // filter without OAuth2AuthProvider as the configured auth.provider.
        Object sharedTokenIntrospection = context.getAttribute(OAuth2AuthProvider.ATTRIBUTE_TOKEN_INTROSPECTION);
        if (sharedTokenIntrospection instanceof TokenIntrospection shared) {
            tokenIntrospection = shared;
        } else {
            tokenIntrospection = new TokenIntrospection(authSettings);
        }
        userInfo = new UserInfo(authSettings);
        registerUserLocally = authSettings.getBoolean(TAG_REGISTER_USER_LOCALLY, OAuth2AuthProvider.class);
        if (registerUserLocally) {
            databaseHandler = DatabaseHandler.getInstance(coreSettings);
        }

        String realmName = authSettings.get(TAG_AUTH_REALM_NAME, OAuth2AuthProvider.class);
        authHeaderValue = "Bearer realm=\"" + realmName + "\"";

        final AuthChecker allAllowed = (userData, response) -> true;
        methodCheckers.put(HttpMethod.OPTIONS, allAllowed);
        methodCheckers.put(HttpMethod.HEAD, allAllowed);

        if (allowAnonymous) {
            methodCheckers.put(HttpMethod.GET, allAllowed);
        } else {
            methodCheckers.put(HttpMethod.GET, (userData, response) -> requireRole(roleGet, userData, response));
        }

        methodCheckers.put(HttpMethod.POST, (userData, response) -> requireRole(rolePost, userData, response));
        methodCheckers.put(HttpMethod.PATCH, (userData, response) -> requireRole(rolePatch, userData, response));
        methodCheckers.put(HttpMethod.PUT, (userData, response) -> requireRole(rolePut, userData, response));
        methodCheckers.put(HttpMethod.DELETE, (userData, response) -> requireRole(roleDelete, userData, response));
    }

    private UserData getUserData(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String accept = request.getHeader("Accept");
        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        if (authHeader == null || !authHeader.startsWith(AUTH_SCHEME)) {
            LOGGER.debug("No 'Bearer' auth header.");
            if ((accept != null) && (accept.contains("text/html"))) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication scheme 'Bearer' is required");
            } else {
                String[] error = new String[]{authHeaderValue, "charset=\"UTF-8\"", "error_description=\"Authentication scheme 'Bearer' is required\""};
                response.addHeader(AUTHORIZATION_REQUIRED_HEADER, StringUtils.join(error, ","));
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            return USER_DATA_NO_USER;
        }

        String token = authHeader.substring(AUTH_SCHEME.length());
        JsonNode tokenInfo = (JsonNode) tokenIntrospection.getTokenInfo(token);
        String userName = "";

        if (tokenInfo.isEmpty()) {
            LOGGER.info("TokenInfo contains no data");
            if ((accept != null) && (accept.contains("text/html"))) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error obtaining TokenInfo");
            } else {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
            return USER_DATA_NO_USER;
        }

        if (!(tokenInfo.has("active") && tokenInfo.get("active").asBoolean())) {
            LOGGER.info("access token expired");
            if ((accept != null) && (accept.contains("text/html"))) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access Token is expired");
            } else {
                String[] error = new String[]{authHeaderValue, "charset=\"UTF-8\"", "error_description=\"Access Token is expired\""};
                response.addHeader(AUTHORIZATION_REQUIRED_HEADER, StringUtils.join(error, ","));
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
            return USER_DATA_NO_USER;
        }

        if (!tokenInfo.has("sub")) {
            LOGGER.warn("TokenInfo does not contain 'sub' -> The user cannot be identified!");
            if ((accept != null) && (accept.contains("text/html"))) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error in received TokenInfo: The user cannot be identified!");
            } else {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
            return USER_DATA_NO_USER;
        } else {
            userName = tokenInfo.get("sub").asText();
        }

        Set<String> roles = OAuth2Roles.fromTokenInfo(tokenInfo);
        return new UserData(userName, token, roles);

    }

    private boolean requireRole(String roleName, UserData userData, HttpServletResponse response) {
        if (userData.isEmpty()) {
            LOGGER.debug("Rejecting request: No user data.");
            //throwAuthRequired(response);
            return false;
        }

        if (!userData.roles.contains(roleName)) {
            LOGGER.debug("Rejecting request: User {} does not have role {}.", userData.userName, roleName);
            //throwAuthRequired(response);
            return false;
        }
        LOGGER.debug("Accepting request: User {} has role {}.", userData.userName, roleName);
        return true;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) resp;

        final String accept = request.getHeader("Accept");
        final HttpMethod method;
        try {
            method = HttpMethod.valueOf(request.getMethod().toUpperCase());
        } catch (IllegalArgumentException exc) {
            LOGGER.debug("Rejecting request: Unknown method: {}.", request.getMethod());
            LOGGER.trace("", exc);

            if ((accept != null) && (accept.contains("text/html"))) {
                response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "HTTP method not allowed");
            } else {
                response.setStatus(405);
            }
            return;
        }

        final String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        UserData userData = USER_DATA_NO_USER;
        Boolean isAdmin = false;
        String userName = "";
        String token = null;
        JsonNode tokenInfo = null;

        AuthChecker checker = methodCheckers.get(method);
        if (checker == null) {
            LOGGER.debug("Rejecting request: No checker for method: {}.", request.getMethod());
            if ((accept != null) && (accept.contains("text/html"))) {
                response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "HTTP method rejected: No checker configured");
            } else {
                response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            }
            return;
        }

        if (authHeader == null || !authHeader.startsWith(AUTH_SCHEME)) {
            if (checker.isAllowed(USER_DATA_NO_USER, response)) {
                ;//continue
            } else {
                LOGGER.debug("No 'Bearer' auth header.");
                if ((accept != null) && (accept.contains("text/html"))) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication scheme 'Bearer' is required");
                } else {
                    String[] error = new String[]{authHeaderValue, "charset=\"UTF-8\"", "error_description=\"Authentication scheme 'Bearer' is required\""};
                    response.addHeader(AUTHORIZATION_REQUIRED_HEADER, StringUtils.join(error, ","));
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                }
                return;
            }
        } else {
            try {
                token = authHeader.substring(AUTH_SCHEME.length() + 1);
                tokenInfo = (JsonNode) tokenIntrospection.getTokenInfo(token);
            } catch (StringIndexOutOfBoundsException e) {
                LOGGER.debug("No token in Authorization header.");
                if ((accept != null) && (accept.contains("text/html"))) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication scheme 'Bearer' is missing token");
                } else {
                    String[] error = new String[]{authHeaderValue, "charset=\"UTF-8\"", "error_description=\"Authentication scheme 'Bearer' is missing token\""};
                    response.addHeader(AUTHORIZATION_REQUIRED_HEADER, StringUtils.join(error, ","));
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                }
                return;
            }

            if (tokenInfo instanceof IntNode) {
                LOGGER.info("TokenInfo returned error. Please check OAuth2 Plugin configuration!");
                if ((accept != null) && (accept.contains("text/html"))) {
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error obtaining TokenInfo. Please check OAuth2 Plugin configuration!");
                } else {
                    response.setHeader("Content-Type", "text/plain");
                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                    response.getWriter().print("Error obtaining TokenInfo. Please check OAuth2 Plugin configuration!");
                }
                return;
            }

            if (!(tokenInfo.has("active") && tokenInfo.get("active").asBoolean())) {
                LOGGER.info("access token expired");
                if ((accept != null) && (accept.contains("text/html"))) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Access Token is expired");
                } else {
                    String[] error = new String[]{authHeaderValue, "charset=\"UTF-8\"", "error_description=\"Access Token is expired\""};
                    response.addHeader(AUTHORIZATION_REQUIRED_HEADER, StringUtils.join(error, ","));
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                }
                return;
            }

            if (!tokenInfo.has("sub")) {
                LOGGER.warn("TokenInfo does not contain 'sub' -> The user cannot be identified!");
                if ((accept != null) && (accept.contains("text/html"))) {
                    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error in received TokenInfo: The user cannot be identified!");
                } else {
                    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                }
                return;
            } else {
                userName = tokenInfo.get("sub").asText();
                Set<String> roles = OAuth2Roles.fromTokenInfo(tokenInfo);
                if (userName.equalsIgnoreCase(adminUid)) {
                    roles.add(PrincipalExtended.ROLE_ADMIN);
                    isAdmin = true;
                }
                userData = new UserData(userName, token, roles);
            }
        }

        PrincipalExtended pe = new PrincipalExtended(userData.userName, isAdmin, userData.roles);

        /* Add Security Context */
        if (token != null) {
            ObjectMapper tiMapper = new ObjectMapper();
            Map<String, Object> ti = tiMapper.convertValue(tokenInfo, new TypeReference<Map<String, Object>>() {});
            pe.addContextItem("TokenInfo", ti);
            JsonNode userInformation = (JsonNode) userInfo.getUserInfo(token);

            ObjectMapper uiMapper = new ObjectMapper();
            Map<String, Object> ui = uiMapper.convertValue(userInformation, new TypeReference<Map<String, Object>>() {});
            pe.addContextItem("UserInfo", ui);
        }

        if (registerUserLocally && userData != USER_DATA_NO_USER) {
            databaseHandler.enureUserInUsertable(userName);
        }
        if (authenticateOnly || (allowAnonymous && (HttpMethod.GET == method))) {
            RequestWrapper rw = new RequestWrapper(request, pe);
            chain.doFilter(rw, response);
            return;
        }

        if (checker.isAllowed(userData, response)) {
            RequestWrapper rw = new RequestWrapper(request,
                    new PrincipalExtended(userData.userName, isAdmin, userData.roles));
            chain.doFilter(rw, response);
            return;
        }

        if ((accept != null) && (accept.contains("text/html"))) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "You do not have the required permissions - sorry");
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    @Override
    public void destroy() {
        // Always shut down, even when the instance is the shared one from
        // OAuth2AuthProvider: this Filter#destroy() callback is the only
        // reliable cleanup trigger for it (AuthProvider has none), and it
        // fires as the webapp - Provider included - is being torn down.
        tokenIntrospection.shutdown();
    }

    /**
     * An interface for helper classes to check requests.
     */
    private interface AuthChecker {

        /**
         * Check if the request is allowed.
         *
         * @param userData The request to check.
         * @param response The response to use for sending errors back.
         * @return False if the request is not allowed.
         */
        boolean isAllowed(UserData userData, HttpServletResponse response);
    }

}
