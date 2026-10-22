<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=false; section>

<#if section = "header">
    ${""}
<#elseif section = "form">
<div class="login-viewport">
  <section class="hero-panel" aria-label="Información institucional y seguridad">
    <div class="hero-overlay"></div>
    <div class="hero-content">
      <div class="brand-badge" aria-hidden="true">
        <svg class="brand-cross" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M10 2.5h4a1 1 0 0 1 1 1V9h5.5a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H15v5.5a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1V15H3.5a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1H9V3.5a1 1 0 0 1 1-1Z" fill="currentColor"/>
        </svg>
      </div>

      <div class="brand-header">
        <h1 class="brand-title">
          <span>SGSI-ZTA</span>
          <span>Hospital Lab</span>
        </h1>
        <p class="brand-subtitle">Plataforma clínica Zero Trust</p>
      </div>

      <div class="brand-divider" aria-hidden="true"></div>

      <div class="features-list">
        <div class="feature-item">
          <div class="feature-icon-wrapper" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7.5 3v5.5c0 4.6-3.1 8.3-7.5 9.5-4.4-1.2-7.5-4.9-7.5-9.5V6L12 3Z"/><path d="M9 12l2 2 4-4"/></svg>
          </div>
          <div class="feature-text">
            <h2 class="feature-heading">Acceso restringido a personal autorizado</h2>
            <p class="feature-desc">Protegemos la información clínica con controles de seguridad avanzados.</p>
          </div>
        </div>

        <div class="feature-item">
          <div class="feature-icon-wrapper" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.2"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M17 4.5a3 3 0 0 1 0 6M18 20h3.5a5 5 0 0 0-3.5-4.8"/></svg>
          </div>
          <div class="feature-text">
            <h2 class="feature-heading">Autenticación OIDC con doble factor</h2>
            <p class="feature-desc">Un acceso seguro y confiable para tu labor diaria.</p>
          </div>
        </div>

        <div class="feature-item">
          <div class="feature-icon-wrapper" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z"/><path d="M14 3v5h5M9 13h6M9 17h4"/></svg>
          </div>
          <div class="feature-text">
            <h2 class="feature-heading">Registro de auditoría inmutable</h2>
            <p class="feature-desc">Trazabilidad completa de todas las operaciones.</p>
          </div>
        </div>
      </div>
    </div>
  </section>

  <section class="form-panel" aria-label="Formulario de inicio de sesión">
    <div class="form-scroll-container">
      <div class="form-box">
        <header class="form-header">
          <h2 class="form-title">${msg("sgsiSignInTitle")}</h2>
          <p class="form-subtitle">${msg("sgsiSignInSubtitle")}</p>
        </header>

        <#if message?has_content && message.type = 'error'>
          <div class="feedback-alert error-alert" role="alert">
            <svg class="alert-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/></svg>
            <span>${message.summary!""}</span>
          </div>
        </#if>

        <form id="kc-form-login" class="login-form" action="${url.loginAction}" method="post">
          <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>

          <div class="form-group">
            <label for="username" class="input-label">${msg("sgsiUsernameLabel")}</label>
            <div class="input-container">
              <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="3.4"/><path d="M4.5 20a7.5 7.5 0 0 1 15 0"/></svg>
              <input id="username" name="username" type="text" class="sgsi-input" autofocus autocomplete="username" value="${(login.username!'')}" placeholder="${msg('sgsiUsernamePlaceholder')}"/>
            </div>
            <#if messagesPerField.existsError('username')>
              <span class="sgsi-field-error">${messagesPerField.getFirstError('username')}</span>
            </#if>
          </div>

          <div class="form-group">
            <label for="password" class="input-label">${msg("sgsiPasswordLabel")}</label>
            <div class="input-container">
              <svg class="input-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
              <input id="password" name="password" type="password" class="sgsi-input" autocomplete="current-password" placeholder="${msg('sgsiPasswordPlaceholder')}"/>
              <span class="icon-button visibility-toggle" role="img" aria-label="${msg('sgsiPasswordLabel')}">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
              </span>
            </div>
            <#if messagesPerField.existsError('password')>
              <span class="sgsi-field-error">${messagesPerField.getFirstError('password')}</span>
            </#if>
          </div>

          <div class="forgot-row">
            <span class="link-button forgot-link" title="${msg('sgsiForgotPasswordNote')}">${msg("sgsiForgotPassword")}</span>
          </div>

          <button id="kc-login" name="login" type="submit" class="action-button primary-btn" aria-label="${msg('sgsiSignInTitle')}">
            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><path d="M10 17l5-5-5-5"/><path d="M15 12H3"/></svg>
            <span>${msg("sgsiSignInAction")}</span>
          </button>

          <div class="divider" aria-hidden="true">
            <span>${msg("sgsiOr")}</span>
          </div>

          <a class="action-button secondary-btn" href="${client.baseUrl!'#'}solicitud-cuenta">
            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.2"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M19 8v6M16 11h6"/></svg>
            <span>${msg("sgsiRequestAccount")}</span>
          </a>

          <div class="callout-card" role="note">
            <svg class="callout-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>
            <div class="callout-content">
              <p class="callout-primary">${msg("sgsiAccountsNoteTitle")}</p>
              <p class="callout-secondary">${msg("sgsiAccountsNoteBody")}</p>
            </div>
          </div>

          <footer class="form-footer">
            <svg class="footer-help-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9.2 9.3a2.9 2.9 0 0 1 5.6 1c0 1.9-2.8 2.4-2.8 2.4M12 16.5h.01"/></svg>
            <span>${msg("sgsiSupportPrompt")}</span>
            <span class="link-button footer-link">${msg("sgsiSupportLink")}</span>
          </footer>
        </form>
      </div>
    </div>
  </section>
</div>
</#if>

</@layout.registrationLayout>