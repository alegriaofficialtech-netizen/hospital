<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#import "social-providers.ftl" as identityProviders>
<#import "passkeys.ftl" as passkeys>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=true; section>

    <#if section = "header">
        ${msg("doLogIn")}
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <#if realm.password>
                    <form id="kc-form-login" class="${properties.kcFormClass!}" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post" novalidate="novalidate">
                        <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>

                        <div class="sgsi-field">
                            <label class="sgsi-label" for="username">${msg("usernameOrEmail")}</label>
                            <div class="sgsi-control-wrap">
                                <span class="sgsi-control-icon" aria-hidden="true">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                                </span>
                                <input id="username" name="username" class="sgsi-control" type="text" autofocus autocomplete="username" value="${(login.username!'')}" placeholder="${msg('sgsiUsernamePlaceholder')}"/>
                            </div>
                        </div>

                        <div class="sgsi-field">
                            <label class="sgsi-label" for="password">${msg("password")}</label>
                            <div class="sgsi-control-wrap">
                                <span class="sgsi-control-icon" aria-hidden="true">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
                                </span>
                                <input id="password" name="password" class="sgsi-control" type="password" autocomplete="current-password" placeholder="${msg('sgsiPasswordPlaceholder')}"/>
                                <button class="sgsi-toggle" type="button" aria-label="${msg('sgsiShowPassword')}" data-sgsi-toggle-password>
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
                                </button>
                            </div>
                            <#if messagesPerField.existsError('username','password')>
                                <span class="sgsi-error" id="input-error-username">${messagesPerField.getFirstError('username','password')}</span>
                            </#if>
                        </div>

                        <div class="sgsi-forgot">
                            <span>${msg("doForgotPassword")}</span>
                        </div>

                        <button id="kc-login" name="login" type="submit" class="sgsi-btn sgsi-btn-primary sgsi-btn-block">
                            <span class="sgsi-btn-icon" aria-hidden="true">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><path d="M10 17l5-5-5-5"/><path d="M15 12H3"/></svg>
                            </span>
                            ${msg("doLogIn")}
                        </button>
                    </form>
                </#if>
            </div>
        </div>
        <script src="${url.resourcesPath}/js/sgsi-login.js"></script>
        <@passkeys.conditionalUIData />
    <#elseif section = "socialProviders">
        <#if realm.password && social.providers?? && social.providers?has_content>
            <@identityProviders.show social=social/>
        </#if>
    <#elseif section = "info">
        <div class="sgsi-divider"><span>${msg("sgsiOr")}</span></div>
        <div class="sgsi-request">
            <span class="sgsi-request-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.2"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M19 8v6M16 11h6"/></svg>
            </span>
            <span>${msg("doRegister")}</span>
        </div>
        <div class="sgsi-note">
            <span class="sgsi-note-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>
            </span>
            <div>
                <strong>${msg("sgsiNoteTitle")}</strong>
                <p>${msg("sgsiNoteBody")}</p>
            </div>
        </div>
        <div class="sgsi-help">
            <span class="sgsi-help-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9.2 9.3a2.9 2.9 0 0 1 5.6 1c0 1.9-2.8 2.4-2.8 2.4M12 16.5h.01"/></svg>
            </span>
            <span>${msg("sgsiHelp")} <a href="${url.sgsiSupportUrl!'#'}">${msg("sgsiSupportLink")}</a></span>
        </div>
    </#if>

</@layout.registrationLayout>
