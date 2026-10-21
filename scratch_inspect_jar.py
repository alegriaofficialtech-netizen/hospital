import zipfile, subprocess, os, re

subprocess.run(["docker", "cp", "sgsi-zta-hospital-lab-keycloak-1:/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.8.0.jar", "/tmp/kc.jar"], check=True)
with zipfile.ZipFile("/tmp/kc.jar") as z:
    b = z.read("org/keycloak/protocol/oidc/utils/AmrUtils.class")
    strings = re.findall(rb'[\x20-\x7e]{3,}', b)
    for s in strings:
        print("  ", s.decode("latin1"))
os.remove("/tmp/kc.jar")
