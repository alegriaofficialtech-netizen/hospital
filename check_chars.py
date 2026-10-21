import re
# check characters of totp_secret
# In Keycloak, the secret in CONFIGURE_TOTP:
# Sometimes Keycloak shows: JBSWY3DPEHPK3PXP or groups of 4: JBSW Y3DP EHPK 3PXP
# Or is it in uppercase or does it contain '-'?
EOF
