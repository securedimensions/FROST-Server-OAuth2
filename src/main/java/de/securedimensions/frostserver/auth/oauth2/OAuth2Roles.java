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

import java.util.HashSet;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/**
 * Maps OAuth2 / AUTHENIX scopes from TokenInfo onto FROST role names.
 * AUTHENIX resource scopes look like {@code citiobs.secd.eu#create}; FROST CUD
 * checks for {@code create}.
 */
final class OAuth2Roles {

    private OAuth2Roles() {
        // Utility class.
    }

    static Set<String> fromTokenInfo(JsonNode tokenInfo) {
        Set<String> roles = new HashSet<>();
        addScopeNode(roles, tokenInfo == null ? null : tokenInfo.get("scope"));
        addScopeNode(roles, tokenInfo == null ? null : tokenInfo.get("scp"));
        return roles;
    }

    private static void addScopeNode(Set<String> roles, JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return;
        }
        if (node.isArray()) {
            for (JsonNode item : node) {
                addScopeString(roles, item.asText(""));
            }
            return;
        }
        addScopeString(roles, node.asText(""));
    }

    private static void addScopeString(Set<String> roles, String raw) {
        if (raw == null || raw.isBlank()) {
            return;
        }
        for (String part : raw.trim().split("\\s+")) {
            if (part.isEmpty()) {
                continue;
            }
            roles.add(part);
            int hash = part.lastIndexOf('#');
            if (hash >= 0 && hash < part.length() - 1) {
                roles.add(part.substring(hash + 1));
            }
        }
    }
}
