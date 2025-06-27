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

import com.fasterxml.jackson.databind.JsonNode;
import de.fraunhofer.iosb.ilt.frostserver.persistence.PersistenceManager;
import de.fraunhofer.iosb.ilt.frostserver.service.InitResult;
import de.fraunhofer.iosb.ilt.frostserver.settings.ConfigDefaults;
import de.fraunhofer.iosb.ilt.frostserver.settings.CoreSettings;
import de.fraunhofer.iosb.ilt.frostserver.settings.Settings;
import de.fraunhofer.iosb.ilt.frostserver.settings.annotation.DefaultValue;
import de.fraunhofer.iosb.ilt.frostserver.settings.annotation.DefaultValueBoolean;
import de.fraunhofer.iosb.ilt.frostserver.settings.annotation.DefaultValueInt;
import de.fraunhofer.iosb.ilt.frostserver.util.AuthProvider;
import de.fraunhofer.iosb.ilt.frostserver.util.LiquibaseUser;
import de.fraunhofer.iosb.ilt.frostserver.util.exception.UpgradeFailedException;
import de.fraunhofer.iosb.ilt.frostserver.util.user.PrincipalExtended;
import de.fraunhofer.iosb.ilt.frostserver.util.user.UserClientInfo;
import java.io.IOException;
import java.io.Writer;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A FROST Auth implementation for OAuth2 Authentication.
 */
public class OAuth2AuthProvider implements AuthProvider, LiquibaseUser, ConfigDefaults {

    @DefaultValueInt(10)
    public static final String TAG_MAX_CLIENTS_PER_USER = "maxClientsPerUser";
    @DefaultValue("FROST-Server")
    public static final String TAG_AUTH_REALM_NAME = "realmName";
    @DefaultValue(PrincipalExtended.ROLE_READ)
    public static final String TAG_HTTP_ROLE_GET = "roleGet";
    @DefaultValue(PrincipalExtended.ROLE_UPDATE)
    public static final String TAG_HTTP_ROLE_PATCH = "rolePatch";
    @DefaultValue(PrincipalExtended.ROLE_CREATE)
    public static final String TAG_HTTP_ROLE_POST = "rolePost";
    @DefaultValue(PrincipalExtended.ROLE_UPDATE)
    public static final String TAG_HTTP_ROLE_PUT = "rolePut";
    @DefaultValue(PrincipalExtended.ROLE_DELETE)
    public static final String TAG_HTTP_ROLE_DELETE = "roleDelete";

    @DefaultValue("n/a")
    public static final String TAG_ADMIN_UID = "adminUid";

    @DefaultValueBoolean(false)
    public static final String TAG_REGISTER_USER_LOCALLY = "registerUserLocally";

    @DefaultValue("USERS")
    public static final String TAG_USER_TABLE = "userTable";

    @DefaultValue("USER_NAME")
    public static final String TAG_USERNAME_COLUMN = "usernameColumn";

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2AuthProvider.class);
    private final Map<String, UserClientInfo> clientidToUserinfo = new ConcurrentHashMap<>();
    private final Map<String, UserClientInfo> usernameToUserinfo = new ConcurrentHashMap<>();
    private CoreSettings coreSettings;
    private int maxClientsPerUser;
    private boolean registerUserLocally;
    private DatabaseHandler databaseHandler;

    private String adminUid;
    private TokenIntrospection tokenIntrospection;

    @Override
    public InitResult init(CoreSettings coreSettings) {
        this.coreSettings = coreSettings;
        final Settings authSettings = coreSettings.getAuthSettings();
        maxClientsPerUser = authSettings.getInt(TAG_MAX_CLIENTS_PER_USER, getClass());
        LOGGER.info("OAuth2 Provider setting {}, set to value: {}", TAG_MAX_CLIENTS_PER_USER, maxClientsPerUser);
        adminUid = authSettings.get(TAG_ADMIN_UID, getClass());
        LOGGER.info("OAuth2 Provider setting {}, set to value: {}", TAG_ADMIN_UID, adminUid);
        tokenIntrospection = new TokenIntrospection(authSettings);
        registerUserLocally = authSettings.getBoolean(TAG_REGISTER_USER_LOCALLY, OAuth2AuthProvider.class);
        if (registerUserLocally) {
            DatabaseHandler.init(coreSettings);
            databaseHandler = DatabaseHandler.getInstance(coreSettings);
        }
        return InitResult.INIT_OK;
    }

    @Override
    public String checkForUpgrades(Map<String, Object> map) {
        return null;
    }

    @Override
    public boolean doUpgrades(Writer writer, Map<String, Object> map) throws UpgradeFailedException, IOException {
        return false;
    }

    @Override
    public Map<String, Object> createLiqibaseParams(PersistenceManager persistenceManager, Map<String, Object> map) {
        return null;
    }

    @Override
    public void addFilter(Object context, CoreSettings coreSettings) {
        OAuth2AuthFilterHelper.createFilter(context, coreSettings);
    }

    @Override
    public boolean isValidUser(String clientId, String userName, String password) {
        LOGGER.debug("isUserValid()");
        if (((userName != null) && !userName.isEmpty()) && !userName.equalsIgnoreCase("BEARER")) {
            LOGGER.info("username must either be empty or be set to 'Bearer'");
            return false;
        }

        JsonNode tokenInfo = tokenIntrospection.getTokenInfo(password);

        if (tokenInfo.isEmpty()) {
            LOGGER.info("TokenInfo contains no data");
            return false;
        }

        if (!(tokenInfo.has("active") && tokenInfo.get("active").asBoolean())) {
            LOGGER.info("access token expired");
            return false;
        }

        if (!tokenInfo.has("sub")) {
            LOGGER.warn("TokenInfo does not contain 'sub' -> The user cannot be identified!");
            return false;
        } else {
            userName = tokenInfo.get("sub").asText();
        }

        boolean admin = userName.equalsIgnoreCase(adminUid);
        Set<String> roles = new HashSet<>(List.of(tokenInfo.get("scope").asText("").split(" ")));
        if (admin) {
            roles.add(PrincipalExtended.ROLE_ADMIN);
        }
        final UserData userData = new UserData(userName, password, roles);
        final PrincipalExtended userPrincipal = new PrincipalExtended(userData.userName, admin, userData.roles);
        final UserClientInfo userInfo = usernameToUserinfo.computeIfAbsent(userData.userName, t -> new UserClientInfo());
        userInfo.setUserPrincipal(userPrincipal);

        if (registerUserLocally) {
            databaseHandler.enureUserInUsertable(userData.userName);
        }

        String oldClientId = userInfo.addClientId(clientId, maxClientsPerUser);
        if (oldClientId != null) {
            clientidToUserinfo.remove(oldClientId);
        }
        clientidToUserinfo.put(clientId, userInfo);
        return true;
    }

    @Override
    public boolean userHasRole(String clientId, String userName, String roleName) {
        LOGGER.debug("userHasRole() for userName={}", userName);
        PrincipalExtended userPrincipal = getUserPrincipal(clientId);
        LOGGER.debug("user roles: {}", userPrincipal.getRoles());
        return userPrincipal.getRoles().contains(roleName);
    }

    @Override
    public PrincipalExtended getUserPrincipal(String clientId) {
        UserClientInfo userInfo = clientidToUserinfo.get(clientId);
        if (userInfo == null) {
            return PrincipalExtended.ANONYMOUS_PRINCIPAL;
        }
        return userInfo.getUserPrincipal();
    }

}
