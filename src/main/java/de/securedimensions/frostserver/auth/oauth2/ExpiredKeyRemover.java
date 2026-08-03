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

/*
From https://stackoverflow.com/questions/49560258/is-there-an-expiring-map-in-java-that-expires-elements-after-a-period-of-time-si
 */

import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;

public class ExpiredKeyRemover implements Runnable {

    private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(ExpiredKeyRemover.class);
    private final ConcurrentHashMap<ExpiringKey<String>, JsonNode> map;

    public ExpiredKeyRemover(ConcurrentHashMap<ExpiringKey<String>, JsonNode> map) {
        this.map = map;
    }

    @Override
    public void run() {
        try {
            Iterator<ExpiringKey<String>> it = map.keySet().iterator();
            while (it.hasNext()) {
                if (it.next().isExpired()) {
                    it.remove();
                }
            }
        } catch (java.lang.IllegalStateException e) {
            LOGGER.warn("Exception starting ExpiredKeyRemover");
        }
    }

}
