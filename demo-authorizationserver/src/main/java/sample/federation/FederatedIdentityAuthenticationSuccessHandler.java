/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.federation;

// tag::imports[]
import java.io.IOException;
import java.util.function.Consumer;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
// end::imports[]

/**
 * An {@link AuthenticationSuccessHandler} for capturing the {@link OidcUser} or
 * {@link OAuth2User} for Federated Account Linking or JIT Account Provisioning.
 *
 * @author Steve Riesenberg
 * @since 1.1
 */
// tag::class[]
public final class FederatedIdentityAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

	private final Consumer<OAuth2User> oauth2UserHandler = new UserRepositoryOAuth2UserHandler();

	private Consumer<OidcUser> oidcUserHandler = (user) -> this.oauth2UserHandler.accept(user);

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		if (authentication instanceof OAuth2AuthenticationToken) {
			if (authentication.getPrincipal() instanceof OidcUser) {
				this.oidcUserHandler.accept((OidcUser) authentication.getPrincipal());
			} else if (authentication.getPrincipal() instanceof OAuth2User) {
				this.oauth2UserHandler.accept((OAuth2User) authentication.getPrincipal());
			}
		}

		this.delegate.onAuthenticationSuccess(request, response, authentication);
	}

}
// end::class[]
