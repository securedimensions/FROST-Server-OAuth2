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

import de.fraunhofer.iosb.ilt.frostserver.request.Version;
import de.fraunhofer.iosb.ilt.frostserver.settings.CoreSettings;
import de.fraunhofer.iosb.ilt.frostserver.util.AuthUtils;
import de.fraunhofer.iosb.ilt.frostserver.util.AuthUtils.Role;
import de.fraunhofer.iosb.ilt.settings.Settings;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterRegistration;
import jakarta.servlet.ServletContext;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

public class OAuth2AuthFilterHelper {

    private OAuth2AuthFilterHelper() {
        // Utility class.
    }

    public static void createFilter(Object context, CoreSettings coreSettings) {
        if (!(context instanceof final ServletContext servletContext)) {
            throw new IllegalArgumentException("Context must be a ServletContext to add Filter.");
        }
        final Settings authSettings = coreSettings.getAuthSettings();
        final boolean authOnly = authSettings.getBoolean(TAG_AUTHENTICATE_ONLY, CoreSettings.class);
        final String adminUid = authSettings.get(TAG_ADMIN_UID, OAuth2AuthProvider.class);

        final Map<AuthUtils.Role, String> roleMapping = AuthUtils.loadRoleMapping(authSettings);
        final String filterClass = OAuth2AuthFilter.class.getName();

        final Map<String, Version> versions = coreSettings.getPluginManager().getVersions();
        final List<String> urlPatterns = new ArrayList<>();
        for (Version version : versions.values()) {
            urlPatterns.add("/" + version.urlPart);
            urlPatterns.add("/" + version.urlPart + "/*");
        }

        String filterName = "OAuth2FilterSta";
        FilterRegistration.Dynamic authFilterSta = servletContext.addFilter(filterName, filterClass);
        final boolean anonRead = authSettings.getBoolean(TAG_AUTH_ALLOW_ANON_READ, CoreSettings.class);
        authFilterSta.setInitParameter(TAG_AUTHENTICATE_ONLY, authOnly ? "T" : "F");
        authFilterSta.setInitParameter(TAG_AUTH_ALLOW_ANON_READ, anonRead ? "T" : "F");
        authFilterSta.setInitParameter(TAG_HTTP_ROLE_GET, roleMapping.get(Role.READ));
        authFilterSta.setInitParameter(TAG_HTTP_ROLE_PATCH, roleMapping.get(Role.UPDATE));
        authFilterSta.setInitParameter(TAG_HTTP_ROLE_POST, roleMapping.get(Role.CREATE));
        authFilterSta.setInitParameter(TAG_HTTP_ROLE_PUT, roleMapping.get(Role.UPDATE));
        authFilterSta.setInitParameter(TAG_HTTP_ROLE_DELETE, roleMapping.get(Role.DELETE));
        authFilterSta.setInitParameter(TAG_AUTH_ROLE_ADMIN, roleMapping.get(Role.ADMIN));
        authFilterSta.setInitParameter(TAG_ADMIN_UID, adminUid);

        authFilterSta.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD), true, urlPatterns.toArray(String[]::new));
    }
}
