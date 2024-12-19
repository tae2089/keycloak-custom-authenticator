package com.example.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.LinkedList;
import java.util.List;

public class ValidateOTP extends AbstractDirectGrantAuthenticator implements CredentialValidator<OTPCredentialProvider> {

    public static final String PROVIDER_ID = "direct-grant-validate-new-otp";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (!configuredFor(context.getSession(), context.getRealm(), context.getUser())) {
            if (context.getExecution().isConditional()) {
                context.attempted();
            } else if (context.getExecution().isRequired()) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid otp");
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            }
            return;
        }
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();

        String otp = inputData.getFirst("otp");

        // KEYCLOAK-12908 Backwards compatibility. If paramter "otp" is null, then assign "totp".
        otp = (otp == null) ? inputData.getFirst("totp") : otp;

        // Always use default OTP credential in case of direct grant authentication
        String credentialId = getCredentialProvider(context.getSession())
                    .getDefaultCredential(context.getSession(), context.getRealm(), context.getUser()).getId();

        if (otp == null) {
            if (context.getUser() != null) {
                context.getEvent().user(context.getUser());
            }
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid otp");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
        boolean valid = getCredentialProvider(context.getSession()).isValid(context.getRealm(), context.getUser(), new UserCredentialModel(credentialId, OTPCredentialModel.TYPE, otp));
        if (!valid) {
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid otp");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return getCredentialProvider(session).isConfiguredFor(realm, user);
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public String getDisplayType() {
        return "OTP";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getHelpText() {
        return "Validates the one time password supplied as a 'totp' form parameter in direct grant request";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return new LinkedList<>();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    public OTPCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (OTPCredentialProvider)session.getProvider(CredentialProvider.class, "keycloak-otp");
    }

}