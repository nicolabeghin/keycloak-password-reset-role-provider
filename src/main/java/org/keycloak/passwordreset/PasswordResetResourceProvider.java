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

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.admin.UserResource;
import org.keycloak.util.JsonSerialization;

/**
 * One operation: send a user a {@code UPDATE_PASSWORD} action email.
 *
 * <p>This exists because Keycloak cannot express "may only trigger a password reset" as a role.
 * The built-in {@code PUT /admin/realms/{realm}/users/{id}/execute-actions-email} requires
 * {@code realm-management:manage-users}, which also grants setting an arbitrary password, rewriting
 * a user's email or username, disabling, deleting and enumerating every user. Fine-grained admin
 * permissions v2 added a {@code reset-password} scope in Keycloak 26.4, but it governs
 * {@code PUT /users/{id}/reset-password} and <em>not</em> {@code execute-actions-email}
 * (upstream keycloak/keycloak#51411, still open).
 *
 * <p>Two properties make this narrow:
 * <ul>
 *   <li>Authorization is a single custom realm role, never a {@code realm-management} role.</li>
 *   <li>The action list is the hardcoded constant {@link #ACTIONS}. It is never read from the
 *       request, so no caller can substitute {@code UPDATE_EMAIL}, {@code delete_credential} or
 *       {@code CONFIGURE_TOTP}.</li>
 * </ul>
 *
 * <p>Cross-realm access is impossible by construction: the resource is mounted under
 * {@code /realms/{realm}/} and {@link AppAuthManager.BearerTokenAuthenticator} resolves the realm
 * from the request context, so a token minted by realm A cannot authenticate against realm B.
 *
 * <p>User state is never disclosed. An unknown, disabled or email-less user yields the same
 * {@code 204} as a successful send; the real outcome goes to the server log and to a realm event.
 * Only caller-configuration errors (bad {@code lifespan}, {@code client_id} or {@code redirect_uri},
 * missing username) produce a {@code 400}, and those are independent of whether the user exists.
 */
public class PasswordResetResourceProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(PasswordResetResourceProvider.class);

    private static final String UPDATE_PASSWORD = UserModel.RequiredAction.UPDATE_PASSWORD.name();

    /**
     * The whole security property of this provider. Never build this from request input.
     */
    private static final List<String> ACTIONS = List.of(UPDATE_PASSWORD);

    private static final String EVENT_DETAIL_VIA = "via";
    private static final String EVENT_DETAIL_VIA_VALUE = "password-reset-role-provider";

    private final KeycloakSession session;
    private final String requiredRole;
    private final int maxLifespanSeconds;

    public PasswordResetResourceProvider(KeycloakSession session, String requiredRole, int maxLifespanSeconds) {
        this.session = session;
        this.requiredRole = requiredRole;
        this.maxLifespanSeconds = maxLifespanSeconds;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    /**
     * {@code POST /realms/{realm}/password-reset}, body {@code {"username": "..."}}.
     *
     * <p>Query parameters mirror the admin endpoint this replaces and are relayed with upstream
     * semantics, except that {@code lifespan} is capped at {@code maxLifespanSeconds}.
     *
     * <p>The body is taken as a {@code String} and deserialized by hand rather than declared as a
     * typed JAX-RS parameter. This keeps the method signature free of types that the build-time
     * scan would have to resolve, and gives a clean {@code 400} on malformed JSON instead of
     * whatever the framework's default body-reader error happens to be.
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response triggerPasswordReset(@QueryParam("redirect_uri") String redirectUri,
                                         @QueryParam("client_id") String clientId,
                                         @QueryParam("lifespan") String lifespanParam,
                                         String body) {

        // 1. Authenticate. Resolves the realm from the request context, which is what confines a
        //    credential to the realm whose URL it was presented to.
        AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null) {
            throw new NotAuthorizedException("Bearer");
        }

        RealmModel realm = session.getContext().getRealm();

        // 2. Authorize on the custom realm role, failing closed if the role is absent.
        RoleModel role = realm.getRole(requiredRole);
        if (role == null) {
            logger.errorf("Realm '%s' has no role '%s': refusing every %s request to this realm. "
                            + "Create the realm role to enable the endpoint.",
                    realm.getName(), requiredRole, PasswordResetResourceProviderFactory.ID);
            throw ErrorResponse.error("Forbidden", Status.FORBIDDEN);
        }
        UserModel caller = auth.user();
        if (caller == null || !caller.hasRole(role)) {
            logger.warnf("Caller '%s' (client '%s') lacks realm role '%s' in realm '%s'",
                    caller == null ? "<none>" : caller.getUsername(),
                    auth.client() == null ? "<none>" : auth.client().getClientId(),
                    requiredRole, realm.getName());
            throw ErrorResponse.error("Forbidden", Status.FORBIDDEN);
        }

        // 3. Validate caller input. These errors are safe to report: none of them depends on
        //    whether the target user exists.
        Integer lifespan = parseLifespan(lifespanParam);
        String username = parseUsername(body);

        // A realm with UPDATE_PASSWORD disabled would send a link that does nothing. That is a
        // realm misconfiguration, not a per-user condition, so report it.
        RequiredActionProviderModel requiredAction = realm.getRequiredActionProviderByAlias(UPDATE_PASSWORD);
        if (requiredAction == null || !requiredAction.isEnabled()) {
            logger.errorf("Required action %s is not enabled in realm '%s'", UPDATE_PASSWORD, realm.getName());
            throw ErrorResponse.error("Required action " + UPDATE_PASSWORD + " is not enabled in this realm",
                    Status.INTERNAL_SERVER_ERROR);
        }

        EventBuilder event = new EventBuilder(realm, session)
                .event(EventType.SEND_RESET_PASSWORD)
                .client(auth.client())
                .detail(EVENT_DETAIL_VIA, EVENT_DETAIL_VIA_VALUE)
                .detail(Details.USERNAME, username);

        // 4. Resolve the user. From here on the response is 204 regardless of outcome, so that the
        //    endpoint cannot be used to test whether a username exists.
        UserModel user = session.users().getUserByUsername(realm, username);
        if (user == null) {
            logger.debugf("No user '%s' in realm '%s'; answering 204 without sending", username, realm.getName());
            event.error(Errors.USER_NOT_FOUND);
            return Response.noContent().build();
        }
        if (!user.isEnabled()) {
            logger.debugf("User '%s' in realm '%s' is disabled; answering 204 without sending",
                    username, realm.getName());
            event.user(user).error(Errors.USER_DISABLED);
            return Response.noContent().build();
        }
        if (user.getEmail() == null || user.getEmail().isBlank()) {
            logger.debugf("User '%s' in realm '%s' has no email; answering 204 without sending",
                    username, realm.getName());
            event.user(user).error(Errors.INVALID_EMAIL);
            return Response.noContent().build();
        }

        // 5. Reuse upstream's own validation for client_id / redirect_uri / lifespan defaulting,
        //    rather than reimplementing it. Its first two checks (email present, user enabled) are
        //    already satisfied above, so it can only fail on caller configuration here.
        UserResource.SendEmailParams params =
                UserResource.verifySendEmailParams(session, realm, user, redirectUri, clientId, lifespan);

        int validity = Math.min(params.getLifespan(), maxLifespanSeconds);
        int expiration = Time.currentTime() + validity;

        ExecuteActionsActionToken token = new ExecuteActionsActionToken(
                user.getId(),
                user.getEmail(),
                expiration,
                ACTIONS,
                params.getRedirectUri(),
                params.getClientId());

        try {
            UriBuilder builder = LoginActionsService.actionTokenProcessor(session.getContext().getUri());
            builder.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));
            String link = builder.build(realm.getName()).toString();

            session.getProvider(EmailTemplateProvider.class)
                    .setAttribute(Constants.TEMPLATE_ATTR_REQUIRED_ACTIONS, token.getRequiredActions())
                    .setAttribute(Constants.IGNORE_ACCEPT_LANGUAGE_HEADER, true)
                    .setRealm(realm)
                    .setUser(user)
                    .sendExecuteActions(link, TimeUnit.SECONDS.toMinutes(validity));

            event.user(user).detail(Details.EMAIL, user.getEmail()).success();

            logger.infof("Sent %s email to user '%s' in realm '%s' on behalf of client '%s' (valid %d seconds)",
                    UPDATE_PASSWORD, username, realm.getName(),
                    auth.client() == null ? "<none>" : auth.client().getClientId(), validity);

            return Response.noContent().build();
        } catch (EmailException e) {
            logger.errorf(e, "Failed to send %s email to user '%s' in realm '%s'",
                    UPDATE_PASSWORD, username, realm.getName());
            event.user(user).error(Errors.EMAIL_SEND_FAILED);
            // A mail transport failure is the caller's to retry and says nothing about the user.
            throw ErrorResponse.error("Failed to send password reset email", Status.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * {@code null} when not supplied, so that upstream applies the realm default (which is then
     * capped). Parsed by hand rather than as an {@code Integer} query parameter so that a
     * non-numeric value is a clean {@code 400} instead of a JAX-RS {@code 404}.
     */
    private Integer parseLifespan(String lifespanParam) {
        if (lifespanParam == null || lifespanParam.isBlank()) {
            return null;
        }
        int parsed;
        try {
            parsed = Integer.parseInt(lifespanParam.trim());
        } catch (NumberFormatException e) {
            throw ErrorResponse.error("Invalid lifespan: expected a positive number of seconds", Status.BAD_REQUEST);
        }
        if (parsed <= 0) {
            throw ErrorResponse.error("Invalid lifespan: expected a positive number of seconds", Status.BAD_REQUEST);
        }
        return parsed;
    }

    private String parseUsername(String body) {
        if (body == null || body.isBlank()) {
            throw ErrorResponse.error("Username missing", Status.BAD_REQUEST);
        }
        PasswordResetRequest request;
        try {
            request = JsonSerialization.readValue(body, PasswordResetRequest.class);
        } catch (IOException e) {
            throw ErrorResponse.error("Malformed JSON body", Status.BAD_REQUEST);
        }
        if (request == null || request.username == null || request.username.isBlank()) {
            throw ErrorResponse.error("Username missing", Status.BAD_REQUEST);
        }
        return request.username.trim();
    }

    /**
     * Request body. Unknown properties are ignored on purpose: a caller that sends
     * {@code "actions"} gets it silently dropped rather than honoured. Deserialized at runtime by
     * {@link JsonSerialization}, never as a declared JAX-RS parameter — see
     * {@link #triggerPasswordReset}.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PasswordResetRequest {

        public String username;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }
    }
}
