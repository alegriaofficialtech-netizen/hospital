/* SGSI-ZTA Hospital Lab: mostrar u ocultar la contrasena.
   El campo lo gestiona Keycloak; este script solo alterna el tipo del input. */
(function () {
  'use strict';

  function wire() {
    var toggle = document.querySelector('[data-sgsi-toggle-password]');
    var field = document.getElementById('password');
    if (!toggle || !field || toggle.dataset.sgsiWired === '1') {
      return;
    }
    toggle.dataset.sgsiWired = '1';
    toggle.addEventListener('click', function () {
      var hidden = field.type === 'password';
      field.type = hidden ? 'text' : 'password';
      toggle.setAttribute('aria-pressed', hidden ? 'true' : 'false');
      field.focus();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }
})();
