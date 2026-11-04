/*
 * Copyright 2026 Nicola Beghin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.passwordreset;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Registers {@code POST /realms/{realm}/password-reset}.
 *
 * <p>Configuration, via {@code --spi-realm-restapi-extension-password-reset-<key>=<value>}
 * (the {@code RealmResourceSPI} name is {@code realm-restapi-extension}; Keycloak dash-cases the
 * scope key, so {@code maxLifespanSeconds} is written {@code max-lifespan-seconds} there):
 * <ul>
 *   <li>{@code role} &mdash; the realm role a caller must hold. Default
 *       {@value #DEFAULT_ROLE}. The role is <em>not</em> created by this provider: if it does not
 *       exist in a realm, every request to that realm is refused.</li>
 *   <li>{@code maxLifespanSeconds} &mdash; ceiling for the action-token lifetime, and the value
 *       used when the caller does not pass {@code lifespan}. Default {@value #DEFAULT_MAX_LIFESPAN_SECONDS}.
 *       Without this the effective default would be the realm's
 *       {@code actionTokenGeneratedByAdminLifespan}, which defaults to 12 hours &mdash; a very
 *       long-lived one-click credential sitting in a mailbox.</li>
 * </ul>
 */
public class PasswordResetResourceProviderFactory implements RealmResourceProviderFactory {

    private static final Logger logger = Logger.getLogger(PasswordResetResourceProviderFactory.class);

    /** Provider id, and therefore the URL segment: {@code /realms/{realm}/password-reset}. */
    public static final String ID = "password-reset";

    static final String DEFAULT_ROLE = "trigger-password-reset";
    static final int DEFAULT_MAX_LIFESPAN_SECONDS = 3600;

    private String role = DEFAULT_ROLE;
    private int maxLifespanSeconds = DEFAULT_MAX_LIFESPAN_SECONDS;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new PasswordResetResourceProvider(session, role, maxLifespanSeconds);
    }

    @Override
    public void init(Config.Scope config) {
        if (config != null) {
            String configuredRole = config.get("role", DEFAULT_ROLE);
            if (configuredRole != null && !configuredRole.isBlank()) {
                role = configuredRole.trim();
            }

            Integer configuredMax = config.getInt("maxLifespanSeconds", DEFAULT_MAX_LIFESPAN_SECONDS);
            if (configuredMax == null || configuredMax <= 0) {
                // Fail loudly rather than silently accepting a value that would disable the cap.
                throw new IllegalArgumentException("maxLifespanSeconds must be a positive number of seconds, got: "
                        + configuredMax);
            }
            maxLifespanSeconds = configuredMax;
        }

        logger.infof("%s registered: POST /realms/{realm}/%s requires realm role '%s', action token capped at %d seconds",
                getClass().getSimpleName(), ID, role, maxLifespanSeconds);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    String getRole() {
        return role;
    }

    int getMaxLifespanSeconds() {
        return maxLifespanSeconds;
    }
}
