# Imagen de Keycloak con el tema de acceso del hospital.
#
# La imagen base ya esta en local (sin descarga). Aqui solo se anade el tema,
# que Keycloak lee de /opt/keycloak/themes al arrancar. El contexto de
# construccion es el propio directorio del tema: una sola fuente de verdad.
FROM quay.io/keycloak/keycloak:26.8.0
COPY sgsi-zta /opt/keycloak/themes/sgsi-zta
