"""Pruebas de bootstrap_oci.py: sin red, sin Docker real y sin esperas reales (la espera se inyecta).

`Nube` es un unico "ejecutor" falso que hace de docker (OCI CLI y rclone) y de gh, con estado en memoria.
Los valores centinela (SENTINELA_*) no pueden aparecer jamas en stdout, stderr, argv ni resultado.json.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import bootstrap_oci as b

TENANCY = "ocid1.tenancy.oc1..tenant"
ADMIN = "ocid1.user.oc1..admin"
REGION = "us-ashburn-1"
NS = "nsprueba"
CORREO = "admin@example.com"
CORREO_ALIAS = "admin+claude-code-deployer@example.com"
PEM_ADMIN = "-----BEGIN PRIVATE KEY-----\nSENTINELA_PEM_ADMIN\n-----END PRIVATE KEY-----\n"
PEM_TECNICO = "-----BEGIN PRIVATE KEY-----\nSENTINELA_PEM_TECNICO\n-----END PRIVATE KEY-----\n"
ACCESO_S3, SECRETO_S3 = "SENTINELA_ACCESO_S3", "SENTINELA_SECRETO_S3"
CENTINELAS = ("SENTINELA_PEM_ADMIN", "SENTINELA_PEM_TECNICO", ACCESO_S3, SECRETO_S3)
# llave publica real generada con `oci setup keys`; su huella la calculo openssl (vector independiente del script)
PUBLICA = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnfTtXxlJfdA/FJOqQ9pd
1OBH18t2Tnirz1gQcf3++VJy9efqUQZ3pJF8LHr0Z1FEDmqXrAlf1E1esYheH0JF
jIILL3y2gL2Bmk0z+vyS8dSgrezbjC7vKgqZxYmU0FteDDyTix24xn6RR7FjkD/u
mG7WcUylzZMULhwqr6dexjp/avCWtZgwQwmoDFhV31ilTRvMEJZm4aTR446g0hgW
lU0RtXzBJis5ZlYlEg0QxvqUdRIGPPvT1/AN1wD1CdPIFU0/juGHdzocj9qPKXuI
8iwU2OzbIb72ftfjlhUkhUIPNOiIiUERWR8KzVfeGPIQCS+FKIxKLs5poZufeB3Y
YQIDAQAB
-----END PUBLIC KEY-----
"""
HUELLA_PUBLICA = "05:7c:9b:8c:52:e7:68:b2:68:be:e7:0d:5a:9c:1e:bd"
CAPS_TODAS = ["can-use-api-keys", "can-use-auth-tokens", "can-use-console-password", "can-use-customer-secret-keys",
              "can-use-db-credentials", "can-use-o-auth2-client-credentials", "can-use-smtp-credentials"]
CONFIG = f"""[DEFAULT]
user={ADMIN}
fingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99
tenancy={TENANCY}
region={REGION}
key_file=<path to your private keyfile> # TODO
"""
# stderr real del OCI CLI 3.96.0 (Docker, sin red) cuando el config trae una huella mal formada
ERROR_CONFIG_REAL = """Warning: To increase security of your API key located at /claves/admin.pem, append an extra line with 'OCI_API_KEY' at the end. For more information, refer to https://docs.oracle.com/iaas/Content/API/Concepts/apisigningkey.htm. To suppress the warning, set the env variable SUPPRESS_LABEL_WARNING=True
ERROR: The config file at /cfg/config is invalid:

+Config Errors+-----------+----------------------------------------------------------------------------------+
| Key         | Error     | Hint                                                                             |
+-------------+-----------+----------------------------------------------------------------------------------+
| fingerprint | malformed | openssl rsa -pubout -outform DER -in <path to your private key> | openssl md5 -c |
+-------------+-----------+----------------------------------------------------------------------------------+
"""
SENTENCIAS_ESPERADAS = [
    "Allow group trayecta-go-automatizacion to manage instance-family in compartment trayecta-go-pruebas",
    "Allow group trayecta-go-automatizacion to manage virtual-network-family in compartment trayecta-go-pruebas",
    "Allow group trayecta-go-automatizacion to manage volume-family in compartment trayecta-go-pruebas",
    "Allow group trayecta-go-automatizacion to manage object-family in compartment trayecta-go-pruebas",
    "Allow group trayecta-go-automatizacion to inspect compartments in tenancy where request.operation='ListAvailabilityDomains'",
]
ORDEN_ESCRITURAS = [
    ("iam", "compartment", "create"), ("iam", "group", "create"), ("iam", "user", "create"),
    ("iam", "user", "update-user-capabilities"), ("iam", "group", "add-user"), ("iam", "policy", "create"),
    ("iam", "user", "api-key", "upload"),
    ("os", "bucket", "create"), ("os", "bucket", "create"),
    ("budgets", "budget", "budget", "create"), ("budgets", "budget", "alert-rule", "create"), ("budgets", "budget", "alert-rule", "create"),
    ("iam", "customer-secret-key", "create")]  # la llave S3 va al final: solo si ninguna prueba fallo


class Err(Exception):
    def __init__(self, estado, codigo, mensaje="fallo simulado"):
        super().__init__(codigo)
        self.estado, self.codigo, self.mensaje = estado, codigo, mensaje


class Nube:
    """Docker + OCI CLI + rclone + gh falsos con estado en memoria; se inyecta como `ejecutar` de Arranque."""
    ESCRITURA = {"create", "upload", "update", "add-user", "update-user-capabilities", "delete", "remove-user"}

    def __init__(self, region=REGION, correo_admin=CORREO, exige_correo=False, p1_requiere_respaldo=False, retraso_tecnico=0,
                 retraso_s3=0, tecnico_puede=(), presupuestos_falla=False, llave_cifrada=False, gh_autenticado=True,
                 a1=(4, 24), fallo_s3_create=False, no_rige=False, huella_distinta=False, deniega_403=(), rclone_docker_falla=False,
                 s3_a_ratos=0, s3_sin_buckets=False, tecnico_a_ratos=0):
        # Oracle propaga las llaves por nodos: tras los primeros rechazos acierta a ratos (1 de cada 3 peticiones falla, 2026-11-09)
        self.s3_a_ratos, self.s3_peticiones_a_ratos, self.s3_sin_buckets = s3_a_ratos, 0, s3_sin_buckets
        self.tecnico_a_ratos, self.tecnico_peticiones_a_ratos = tecnico_a_ratos, 0  # lo mismo para la llave de API: 401 intermitentes
        self.huella_distinta = huella_distinta  # Oracle devuelve una huella que no es la de la llave subida
        self.deniega_403, self.rclone_docker_falla = set(deniega_403), rclone_docker_falla  # denegar con 403 en vez de 404; Docker no corre rclone
        self.region_casa, self.correo_admin, self.exige_correo = region, correo_admin, exige_correo
        self.p1_requiere_respaldo, self.retraso_tecnico, self.retraso_s3 = p1_requiere_respaldo, retraso_tecnico, retraso_s3
        self.no_rige = no_rige  # la politica nunca llega a regir: todo 404 para el usuario tecnico
        self.tecnico_puede, self.presupuestos_falla, self.llave_cifrada = set(tecnico_puede), presupuestos_falla, llave_cifrada
        self.gh_autenticado, self.a1, self.fallo_s3_create = gh_autenticado, a1, fallo_s3_create
        self.contador, self.get_restantes = 0, {}
        self.comps, self.grupos, self.membresias, self.politicas = [], [], set(), []
        self.usuarios = [{"id": ADMIN, "name": "admin", "email": correo_admin, "lifecycle-state": "ACTIVE",
                          "capabilities": dict.fromkeys(CAPS_TODAS, True)}]
        self.llaves_api, self.llaves_s3, self.buckets, self.objetos, self.s3_valido = {}, {}, {}, {}, None
        self.presupuestos, self.reglas, self.secretos_gh, self.variables_gh = [], {}, {}, {}
        self.violaciones = []
        self.reiniciar_registros()

    def reiniciar_registros(self):
        self.llamadas, self.linea, self.escrituras, self.oci_log = [], [], [], []
        self.gh_sets, self.borrados, self.env_rclone, self.setup_keys_n = [], [], [], 0

    # ---------------------------------------------------------------- estado de apoyo
    def nuevo(self, prefijo, lista, **campos):
        self.contador += 1
        d = {"id": f"ocid1.{prefijo}.oc1..{self.contador:04d}", "lifecycle-state": "ACTIVE", **campos}
        lista.append(d)
        return d

    def usuario(self, nombre=b.N_USUARIO):
        return next((u for u in self.usuarios if u["name"] == nombre), None)

    def politica(self):
        return next((p for p in self.politicas if p["name"] == b.N_POLITICA), None)

    def comp_id(self):
        return next((c["id"] for c in self.comps if c["name"] == b.N_COMP and c["lifecycle-state"] != "DELETED"), None)

    def precargar(self, comp=False, grupo=False, usuario=False, miembro=False, politica=False, llaves_api=0, s3=False, buckets=False):
        if comp:
            self.nuevo("compartment", self.comps, name=b.N_COMP, **{"compartment-id": TENANCY})
        if grupo:
            self.nuevo("group", self.grupos, name=b.N_GRUPO)
        if usuario:
            u = self.nuevo("user", self.usuarios, name=b.N_USUARIO, email=None, capabilities={k: k in b.CAPACIDADES for k in CAPS_TODAS})
            for i in range(llaves_api):
                self.llaves_api.setdefault(u["id"], []).append({"fingerprint": f"aa:{i:02d}", "key-value": "x", "lifecycle-state": "ACTIVE"})
            if s3:
                self.llaves_s3.setdefault(u["id"], []).append({"display-name": b.N_LLAVE_S3, "id": "otro", "lifecycle-state": "ACTIVE"})
            if miembro and grupo:
                self.membresias.add((u["id"], self.grupos[-1]["id"]))
        if politica:
            self.nuevo("policy", self.politicas, name=b.N_POLITICA, statements=list(b.SENTENCIAS))
        if buckets:
            for n in (b.B_ESTADO, b.B_ARCHIVOS):
                self.buckets[n] = {"name": n, "compartment-id": self.comp_id(), "public-access-type": "NoPublicAccess",
                                   "storage-tier": "Standard", "versioning": "Enabled" if n == b.B_ESTADO else "Disabled"}
                self.objetos[n] = {}

    # ---------------------------------------------------------------- punto de entrada (el "subproceso")
    def __call__(self, argv, entrada=None, env=None, timeout=None):
        self.llamadas.append((list(argv), entrada))
        if argv[0] == "gh":
            return self.gh(argv[1:], entrada)
        assert argv[0] == "docker", argv
        if "--privileged" in argv:
            self.violaciones.append("docker con --privileged")
        for exigida in ("--cap-drop=ALL", "--security-opt=no-new-privileges"):
            if exigida not in argv:
                self.violaciones.append(f"docker sin {exigida}")
        for i, x in enumerate(argv):
            if x == "--mount" and not argv[i + 1].endswith(",readonly") and "setup" not in argv:
                self.violaciones.append(f"montaje de escritura: {argv[i + 1]}")
        if b.IMAGEN_OCI in argv:
            i = argv.index(b.IMAGEN_OCI)
            return self.oci_cli(argv[:i], argv[i + 1:], entrada)
        if b.IMAGEN_RCLONE in argv:
            i = argv.index(b.IMAGEN_RCLONE)
            return self.rclone(argv[:i], argv[i + 1:], entrada, env or {})
        self.violaciones.append(f"imagen desconocida: {argv}")
        return 1, "", "imagen desconocida"

    @staticmethod
    def parsear(resto):
        cmd, i = [], 0
        while i < len(resto) and not resto[i].startswith("-"):
            cmd.append(resto[i])
            i += 1
        o = {}
        while i < len(resto):
            k = {"-c": "--compartment-id"}.get(resto[i], resto[i])
            if k in ("--all", "--force"):
                o[k], i = True, i + 1
            else:
                o[k], i = resto[i + 1], i + 2
        return cmd, o

    def oci_cli(self, flags, args, entrada):
        montajes = [flags[i + 1] for i, f in enumerate(flags) if f == "--mount"]
        if args[0] == "setup":
            return self.setup_keys(montajes, args, entrada)
        assert args[:2] == ["--config-file", "/cfg/config"] and args[4:8] == ["--output", "json", "--auth", "api_key"], args
        perfil, (cmd, o) = args[3], self.parsear(args[8:])
        destinos = [re.search(r"target=([^,]+)", m).group(1) for m in montajes]
        if "OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True" not in flags:
            self.violaciones.append("falta la variable de permisos")
        if perfil == "DEFAULT" and "/claves/admin.pem" not in destinos:
            self.violaciones.append("el administrador no tiene su llave montada")
        if perfil == "TECNICO" and ("/claves/admin.pem" in destinos or "/claves-tecnico" not in destinos):
            self.violaciones.append("el perfil tecnico ve la llave del administrador o no ve la suya")
        self.linea.append(("oci", perfil, tuple(cmd)))
        self.oci_log.append((perfil, tuple(cmd), o))
        if cmd[-1] in self.ESCRITURA:
            self.escrituras.append((perfil, tuple(cmd)))
        try:
            if perfil == "TECNICO":
                self.autoriza(cmd, o)
            d = getattr(self, "h_" + "_".join(cmd).replace("-", "_"))(o)
        except Err as e:
            error = {"code": e.codigo, "message": e.mensaje, "status": e.estado, "opc-request-id": "x"}
            return 1, "", "ServiceError:\n" + json.dumps(error, indent=4)
        return 0, ("" if d is None else json.dumps({"data": d})), ""

    def autoriza(self, cmd, o):
        """Permisos del usuario tecnico derivados de la politica que existe en la nube falsa."""
        tec = self.usuario()
        if not tec or not self.llaves_api.get(tec["id"]) or self.retraso_tecnico > 0:
            self.retraso_tecnico = max(0, self.retraso_tecnico - 1)
            raise Err(401, "NotAuthenticated")
        if self.tecnico_a_ratos > 0:
            self.tecnico_a_ratos -= 1
            self.tecnico_peticiones_a_ratos += 1
            if self.tecnico_peticiones_a_ratos % 3 == 0:
                raise Err(401, "NotAuthenticated")
        if self.no_rige:
            raise Err(404, "NotAuthorizedOrNotFound")
        pol = self.politica()
        st, c, cid = set(pol["statements"]) if pol else set(), " ".join(cmd), o.get("--compartment-id")
        base = set(b.SENT_BASE) <= st
        if c in self.tecnico_puede:
            return
        if c in ("compute image list", "network vcn list", "compute instance list", "bv volume list") and cid == self.comp_id() and base:
            return
        if c == "os object list" and base:
            return
        if c == "iam availability-domain list" and cid == TENANCY and (
                b.SENTENCIAS_RESPALDO[-1] in st or (b.SENTENCIAS[-1] in st and not self.p1_requiere_respaldo)):
            return
        if c == "iam compartment list" and cid == TENANCY:  # accessLevel=ANY (por defecto): Oracle no comprueba permisos (observado el 2026-11-09)
            return
        if c == "iam compartment get" and cid == TENANCY and b.SENTENCIAS_RESPALDO[-1] in st:  # solo `inspect compartments` sin filtro lo permite
            return
        if c in self.deniega_403:
            raise Err(403, "Forbidden", "Forbidden")
        raise Err(404, "NotAuthorizedOrNotFound", "Authorization failed or requested resource not found.")

    # ---------------------------------------------------------------- IAM
    def h_iam_region_subscription_list(self, o):
        return [{"is-home-region": False, "region-name": "us-phoenix-1"}, {"is-home-region": True, "region-name": self.region_casa}]

    def h_os_ns_get(self, o):
        return NS

    def h_iam_user_get(self, o):
        u = next((u for u in self.usuarios if u["id"] == o["--user-id"]), None)
        if not u:
            raise Err(404, "NotAuthorizedOrNotFound")
        return u

    def h_iam_compartment_list(self, o):
        return [c for c in self.comps if c["compartment-id"] == o["--compartment-id"]]

    def h_iam_compartment_create(self, o):
        c = self.nuevo("compartment", self.comps, name=o["--name"], **{"compartment-id": o["--compartment-id"]})
        c["lifecycle-state"], self.get_restantes[c["id"]] = "CREATING", 1  # el primer get aun lo ve CREATING
        return dict(c)

    def h_iam_compartment_get(self, o):
        if o["--compartment-id"] == TENANCY:
            return {"id": TENANCY, "name": "raiz", "lifecycle-state": "ACTIVE"}
        c = next(c for c in self.comps if c["id"] == o["--compartment-id"])
        if self.get_restantes.get(c["id"], 0) > 0:
            self.get_restantes[c["id"]] -= 1
            return dict(c)
        c["lifecycle-state"] = "ACTIVE"
        return dict(c)

    def h_iam_group_list(self, o):
        return self.grupos

    def h_iam_group_create(self, o):
        return self.nuevo("group", self.grupos, name=o["--name"])

    def h_iam_group_add_user(self, o):
        self.membresias.add((o["--user-id"], o["--group-id"]))
        return {"user-id": o["--user-id"], "group-id": o["--group-id"], "lifecycle-state": "ACTIVE"}

    def h_iam_group_list_users(self, o):
        return [u for u in self.usuarios if (u["id"], o["--group-id"]) in self.membresias]

    def h_iam_user_list(self, o):
        return self.usuarios

    def h_iam_user_create(self, o):
        if self.exige_correo and "--email" not in o:
            if self.exige_correo == "idcs":  # respuesta real de un dominio de identidad con el usuario en español (2026-11-09)
                raise Err(400, "IdcsConversionError", 'Post request failed{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],'
                          '"detail":"Se debe especificar el correo electrónico primario.","status":"400"}')
            raise Err(400, "InvalidParameter", "Email is required for users in this tenancy")
        if "--email" in o and o["--email"] != CORREO_ALIAS:
            self.violaciones.append(f"correo distinto del alias del administrador: {o['--email']}")
        return self.nuevo("user", self.usuarios, name=o["--name"], email=o.get("--email"), capabilities=dict.fromkeys(CAPS_TODAS, True))

    def h_iam_user_list_groups(self, o):
        return [g for g in self.grupos if (o["--user-id"], g["id"]) in self.membresias]

    def h_iam_user_update_user_capabilities(self, o):
        u = next(u for u in self.usuarios if u["id"] == o["--user-id"])
        for k, v in o.items():
            if k.startswith("--can-use-"):
                u["capabilities"][k[2:]] = v == "true"
        return u["capabilities"]

    def h_iam_user_api_key_list(self, o):
        return self.llaves_api.get(o["--user-id"], [])

    def h_iam_user_api_key_upload(self, o):
        if len(self.llaves_api.get(o["--user-id"], [])) >= 3:
            raise Err(409, "LimitExceeded")
        der = base64.b64decode("".join(l for l in o["--key"].splitlines() if not l.startswith("-----")))
        h = hashlib.md5(der).hexdigest()
        k = {"fingerprint": ":".join(h[i:i + 2] for i in range(0, 32, 2)), "key-value": o["--key"], "lifecycle-state": "ACTIVE"}
        if self.huella_distinta:
            k["fingerprint"] = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
        self.llaves_api.setdefault(o["--user-id"], []).append(k)
        return k

    def h_iam_customer_secret_key_list(self, o):
        return [{k: v for k, v in x.items() if k != "key"} for x in self.llaves_s3.get(o["--user-id"], [])]

    def h_iam_customer_secret_key_create(self, o):
        if self.fallo_s3_create:
            raise Err(400, "InvalidParameter", f"detalle interno con {SECRETO_S3}")
        k = {"display-name": o["--display-name"], "id": ACCESO_S3, "key": SECRETO_S3, "lifecycle-state": "ACTIVE"}
        self.llaves_s3.setdefault(o["--user-id"], []).append(k)
        self.s3_valido = (ACCESO_S3, SECRETO_S3)
        return k

    def h_iam_policy_list(self, o):
        return self.politicas

    def h_iam_policy_create(self, o):
        return self.nuevo("policy", self.politicas, name=o["--name"], statements=json.loads(o["--statements"]))

    def h_iam_policy_update(self, o):
        if "--force" not in o or "--version-date" not in o:  # el CLI real exige --version-date junto a --statements
            raise Err(400, "MissingParameter")
        p = next(p for p in self.politicas if p["id"] == o["--policy-id"])
        p["statements"] = json.loads(o["--statements"])
        return p

    def h_iam_availability_domain_list(self, o):
        return [{"name": "AD-1"}]

    # ---------------------------------------------------------------- Object Storage, cómputo y red
    def h_os_bucket_get(self, o):
        if o["--bucket-name"] not in self.buckets:
            raise Err(404, "BucketNotFound", "Bucket not found")
        return self.buckets[o["--bucket-name"]]

    def h_os_bucket_create(self, o):
        n = o["--name"]
        self.buckets[n] = {"name": n, "compartment-id": o["--compartment-id"], "public-access-type": o["--public-access-type"],
                           "storage-tier": o["--storage-tier"], "versioning": o.get("--versioning", "Disabled")}
        self.objetos[n] = {}
        return self.buckets[n]

    def h_os_bucket_update(self, o):
        self.buckets[o["--bucket-name"]]["versioning"] = o["--versioning"]
        return self.buckets[o["--bucket-name"]]

    def h_os_object_list(self, o):
        return [{"name": k} for k in self.objetos[o["--bucket-name"]]]

    def h_compute_image_list(self, o):
        return [{"display-name": "Canonical-Ubuntu-24.04-aarch64"}]

    def h_network_vcn_list(self, o):
        return []

    def h_compute_instance_list(self, o):
        return []

    def h_bv_volume_list(self, o):
        return None  # el CLI real puede no imprimir nada cuando la lista esta vacia

    # ---------------------------------------------------------------- presupuestos y limites
    def h_budgets_budget_budget_list(self, o):
        if self.presupuestos_falla:
            raise Err(400, "InvalidParameter", "Budgets not available")
        return self.presupuestos

    def h_budgets_budget_budget_create(self, o):
        if self.presupuestos:  # Oracle limita los presupuestos del tenancy (observado el 2026-11-09: 400 LimitExceeded)
            raise Err(400, "LimitExceeded", "Budget limit exceeded")
        assert o["--target-type"] == "COMPARTMENT" and json.loads(o["--targets"]) == [TENANCY] and o["--amount"] == "1"
        return self.nuevo("budget", self.presupuestos, **{"display-name": o["--display-name"]})

    def h_budgets_budget_alert_rule_list(self, o):
        return self.reglas.get(o["--budget-id"], [])

    def h_budgets_budget_alert_rule_create(self, o):
        assert o["--recipients"] == CORREO and o["--threshold-type"] == "PERCENTAGE"
        r = {"id": f"regla{len(self.reglas.get(o['--budget-id'], []))}", "type": o["--type"], "threshold": float(o["--threshold"]),
             "threshold-type": o["--threshold-type"], "display-name": o["--display-name"]}
        self.reglas.setdefault(o["--budget-id"], []).append(r)
        return r

    def h_limits_value_list(self, o):
        return [{"name": "standard-a1-core-count", "scope-type": "AD", "availability-domain": "AD-1", "value": 4},
                {"name": "standard-a1-memory-count", "scope-type": "AD", "availability-domain": "AD-1", "value": 24},
                {"name": "standard-e4-core-count", "scope-type": "AD", "availability-domain": "AD-1", "value": 0}]

    def h_limits_resource_availability_get(self, o):
        return {"available": self.a1[0] if "core" in o["--limit-name"] else self.a1[1]}

    # ---------------------------------------------------------------- oci setup keys
    def setup_keys(self, montajes, args, entrada):
        self.setup_keys_n += 1
        if args != ["setup", "keys", "--key-name", "api", "--output-dir", "/claves", "--overwrite"]:
            self.violaciones.append(f"setup keys con argumentos inesperados: {args}")
        origen = re.search(r"source=(.+),target=/claves$", next(m for m in montajes if m.endswith("target=/claves"))).group(1)
        cifrada = self.llave_cifrada or entrada != "N/A\nN/A\n"  # solo "N/A" exacto por stdin deja la llave sin cifrar
        cuerpo = ("-----BEGIN ENCRYPTED PRIVATE KEY-----\nSENTINELA_PEM_TECNICO\n-----END ENCRYPTED PRIVATE KEY-----\n" if cifrada else PEM_TECNICO)
        Path(origen, "api.pem").write_text(cuerpo, encoding="utf-8")
        Path(origen, "api_public.pem").write_text(PUBLICA, encoding="utf-8")
        return 0, "", ""

    # ---------------------------------------------------------------- rclone
    def rclone(self, flags, args, entrada, env):
        self.linea.append(("rclone", tuple(args)))
        self.env_rclone.append(dict(env))
        for n in ("RCLONE_CONFIG_OCI_ACCESS_KEY_ID", "RCLONE_CONFIG_OCI_SECRET_ACCESS_KEY"):
            if n not in flags:
                self.violaciones.append(f"falta '-e {n}' sin valor")
        if any(f.startswith(("RCLONE_CONFIG_OCI_ACCESS", "RCLONE_CONFIG_OCI_SECRET")) and "=" in f for f in flags):
            self.violaciones.append("llave S3 en argv")
        # P5 debe probar el mismo endpoint que usan los workflows y Ansible de trayecta-go-infra (el dominio antiguo y el nuevo funcionan igual:
        # medido el 2026-11-09, la causa de los fallos era la propagacion de la llave, no el dominio)
        if f"RCLONE_CONFIG_OCI_ENDPOINT=https://{NS}.compat.objectstorage.{REGION}.oraclecloud.com" not in flags:
            self.violaciones.append("endpoint S3 inesperado")
        if f"RCLONE_CONFIG_OCI_REGION={REGION}" not in flags:
            self.violaciones.append("rclone debe firmar con la region real, no con us-east-1")
        if entrada is not None and "-i" not in flags:
            self.violaciones.append("stdin sin -i")
        if self.rclone_docker_falla:
            return 125, "", "docker: Error response from daemon"
        if self.retraso_s3 > 0:
            self.retraso_s3 -= 1
            return 1, "", "AccessDenied"
        if self.s3_a_ratos > 0:
            self.s3_a_ratos -= 1
            self.s3_peticiones_a_ratos += 1
            if self.s3_peticiones_a_ratos % 3 == 0:
                return 1, "", "SignatureDoesNotMatch"
        if (env.get("RCLONE_CONFIG_OCI_ACCESS_KEY_ID"), env.get("RCLONE_CONFIG_OCI_SECRET_ACCESS_KEY")) != self.s3_valido:
            return 1, "", "SignatureDoesNotMatch"
        if self.s3_sin_buckets:  # la API S3 no ve el bucket (p. ej. fuera del compartimento designado): rclone responde 3
            return 3, "", "directory not found"
        op, (bucket, _, ruta) = args[0], args[1][len("oci:"):].partition("/")
        if bucket not in self.buckets:
            return 3, "", "directory not found"
        obj = self.objetos[bucket]
        if op == "lsf":
            visibles = [k[len(ruta):] for k in obj if k.startswith(ruta)]
            if ruta and not visibles:  # en S3 un prefijo sin objetos no existe: rclone responde 3 (directorio no encontrado)
                return 3, "", "directory not found"
            return 0, "".join(f"{k}\n" for k in visibles), ""
        if op == "rcat":
            if entrada is None or len(entrada.encode()) != 5:
                self.violaciones.append("el objeto de humo debe tener 5 bytes")
            obj[ruta] = entrada
            return 0, "", ""
        if op == "cat":
            return (0, obj[ruta], "") if ruta in obj else (3, "", "object not found")
        if op == "deletefile":
            obj.pop(ruta, None)
            self.borrados.append((bucket, ruta))
            return 0, "", ""
        raise AssertionError(args)

    # ---------------------------------------------------------------- gh
    def gh(self, args, entrada):
        self.linea.append(("gh", tuple(args[:2])))
        if args[:2] == ["auth", "status"]:
            return (0 if self.gh_autenticado else 1), "", ""
        assert args[args.index("--repo") + 1] == b.REPO_INFRA, args
        if args[:2] == ["secret", "list"]:
            return 0, json.dumps([{"name": n} for n in self.secretos_gh]), ""
        if args[:2] == ["variable", "list"]:
            return 0, json.dumps([{"name": n, "value": v} for n, v in self.variables_gh.items()]), ""
        if args[:2] == ["secret", "set"]:
            if not entrada:
                return 1, "", "body cannot be blank"
            self.gh_sets.append(("secret", args[2], entrada))
            self.secretos_gh[args[2]] = entrada
            return 0, "", ""
        if args[:2] == ["variable", "set"]:
            valor = args[args.index("--body") + 1]
            self.gh_sets.append(("variable", args[2], valor))
            self.variables_gh[args[2]] = valor
            return 0, "", ""
        raise AssertionError(args)


class Guion:
    """Ejecutor con respuestas predefinidas, para probar `oci()` en aislamiento."""

    def __init__(self, respuestas):
        self.respuestas, self.llamadas = list(respuestas), []

    def __call__(self, argv, entrada=None, env=None, timeout=None):
        self.llamadas.append(list(argv))
        return self.respuestas.pop(0)


def error_servicio(estado, codigo="Algo", mensaje="detalle"):
    return 1, "", "ServiceError:\n" + json.dumps({"code": codigo, "message": mensaje, "status": estado}, indent=4)


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="test-oci-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.config, self.pem = self.dir / "config", self.dir / "admin.pem"
        self.config.write_text(CONFIG, encoding="utf-8")
        self.pem.write_text(PEM_ADMIN, encoding="utf-8")
        self.dormidos = []
        # cualquier espera real haria fallar la prueba: la espera siempre va por `dormir` inyectado
        p = mock.patch("time.sleep", side_effect=AssertionError("espera real"))
        p.start()
        self.addCleanup(p.stop)

    def correr(self, nube, orden="apply", *extra):
        argv = [orden, "--config", str(self.config), "--clave-admin", str(self.pem), "--salida", str(self.dir / "salida"), *extra]
        arr = b.Arranque(b.crear_parser().parse_args(argv), nube, self.dormidos.append)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            codigo = arr.correr()
        if arr.tmp:
            self.addCleanup(shutil.rmtree, arr.tmp, ignore_errors=True)
        return SimpleNamespace(codigo=codigo, out=out.getvalue(), err=err.getvalue(), arr=arr)

    def sin_escrituras(self, nube):
        self.assertEqual(nube.escrituras, [])
        self.assertEqual(nube.gh_sets, [])
        self.assertEqual(nube.setup_keys_n, 0)
        self.assertEqual(nube.violaciones, [])


class PruebasFlujo(Base):
    def test_sentencias_de_la_politica_son_exactamente_las_acordadas(self):
        self.assertEqual(b.SENTENCIAS, SENTENCIAS_ESPERADAS)
        self.assertEqual(b.SENTENCIAS_RESPALDO[:4], SENTENCIAS_ESPERADAS[:4])
        self.assertEqual(b.SENTENCIAS_RESPALDO[4], "Allow group trayecta-go-automatizacion to inspect compartments in tenancy")

    def test_desde_cero_crea_todo_en_orden_y_carga_github_al_final(self):
        n = Nube()
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual([c for _, c in n.escrituras], ORDEN_ESCRITURAS)
        self.assertTrue(all(p == "DEFAULT" for p, _ in n.escrituras))
        self.assertFalse(any(c[-1] in ("delete", "remove-user") for _, c, _ in n.oci_log), "no hay borrados en OCI")
        self.assertEqual({x[1] for x in n.gh_sets if x[0] == "secret"}, set(b.SECRETOS_GH))
        self.assertEqual([x[1] for x in n.gh_sets if x[0] == "variable"], ["OCI_NAMESPACE", "OCI_REGION"])
        # GitHub solo despues de TODA llamada a Oracle y a rclone (verificacion incluida)
        ultimo = max(i for i, e in enumerate(n.linea) if e[0] in ("oci", "rclone"))
        primero = min(i for i, e in enumerate(n.linea) if e[0] == "gh" and e[1] == ("secret", "set"))
        self.assertGreater(primero, ultimo)
        self.assertEqual({k: v[0] for k, v in r.arr.pruebas.items() if v[0] != "OK"}, {})
        for id_ in ("P1", "P2", "P5", "N1", "N2", "N4", "N6", "N7", "N11", "N12", "N13", "P7", "P8"):
            self.assertEqual(r.arr.pruebas[id_][0], "OK", id_)
        # unico borrado: el objeto de humo que el propio script creo
        self.assertEqual(n.borrados, [(b.B_ARCHIVOS, "humo/prueba.txt")])
        self.assertEqual(n.objetos[b.B_ARCHIVOS], {})
        self.assertEqual(n.violaciones, [])
        self.assertFalse(r.arr.tmp.exists(), "la privada temporal se borra")
        # etiquetas en todo lo que las admite
        etiquetas = {"proyecto": "trayecta-go", "entorno": "pruebas", "gestionado-por": "opentofu", "creado-por": "bootstrap-oci"}
        sin_etiquetas = {("iam", "user", "api-key", "upload"), ("iam", "customer-secret-key", "create")}
        creaciones = [(c, o) for _, c, o in n.oci_log if c[-1] == "create" and c not in sin_etiquetas]
        self.assertEqual(len(creaciones), 9)  # compartimento, grupo, usuario, politica, 2 buckets, presupuesto y 2 alertas
        for c, o in creaciones:
            self.assertEqual(json.loads(o["--freeform-tags"]), etiquetas, c)
        # buckets privados, Standard, en el compartimento; versionado solo en el de estado
        buckets = {o["--name"]: o for _, c, o in n.oci_log if c == ("os", "bucket", "create")}
        self.assertEqual(buckets[b.B_ESTADO]["--versioning"], "Enabled")
        self.assertNotIn("--versioning", buckets[b.B_ARCHIVOS])
        self.assertTrue(all((o["--storage-tier"], o["--public-access-type"], o["--compartment-id"]) == ("Standard", "NoPublicAccess", n.comp_id())
                            for o in buckets.values()))
        # el usuario tecnico queda solo con API keys y llaves S3
        caps = next(o for _, c, o in n.oci_log if c == ("iam", "user", "update-user-capabilities"))
        self.assertEqual({k[2:]: v for k, v in caps.items() if k.startswith("--can-use-")},
                         {k: ("true" if k in b.CAPACIDADES else "false") for k in CAPS_TODAS})
        # el perfil tecnico solo hace lecturas y solo las esperadas
        tecnico = [c for p, c, _ in n.oci_log if p == "TECNICO"]
        self.assertTrue(all(c[-1] in ("list", "get") for c in tecnico))  # solo verbos de lectura
        self.assertEqual(set(tecnico), {("compute", "image", "list"), ("network", "vcn", "list"), ("compute", "instance", "list"), ("bv", "volume", "list"),
                                        ("iam", "availability-domain", "list"), ("os", "object", "list"), ("iam", "compartment", "get"),
                                        ("iam", "user", "list"), ("iam", "policy", "list"), ("budgets", "budget", "budget", "list")})
        res = json.loads((self.dir / "salida" / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual((res["region"], res["namespace"], res["huella_llave_api"]), (REGION, NS, HUELLA_PUBLICA))
        self.assertEqual((self.dir / "salida" / ".gitignore").read_text(), "*\n")
        self.assertEqual(r.arr.faltan, [])
        # las llaves nuevas llegaron a GitHub por stdin y con el contenido exacto
        self.assertEqual(n.secretos_gh["OCI_PRIVATE_KEY"], PEM_TECNICO)
        self.assertEqual((n.secretos_gh["OCI_S3_ACCESS_KEY"], n.secretos_gh["OCI_S3_SECRET_KEY"]), (ACCESO_S3, SECRETO_S3))
        self.assertEqual(n.secretos_gh["OCI_FINGERPRINT"], HUELLA_PUBLICA)

    def test_segunda_ejecucion_no_llama_a_ningun_create(self):
        n = Nube()
        self.assertEqual(self.correr(n).codigo, 0)
        n.reiniciar_registros()
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.sin_escrituras(n)
        self.assertFalse(any(c[-1] in Nube.ESCRITURA for _, c, _ in n.oci_log))
        self.assertIn("No hubo cambios en Oracle", r.out)
        self.assertEqual(r.arr.pruebas["P1"][0], "OMITIDA")  # la privada ya no se puede releer
        self.assertEqual(r.arr.pruebas["P5"][0], "OMITIDA")
        for id_ in ("N11", "N12", "N13", "P7"):
            self.assertEqual(r.arr.pruebas[id_][0], "OK", id_)

    def test_faltan_solo_los_buckets(self):
        n = Nube()
        self.assertEqual(self.correr(n).codigo, 0)
        n.buckets.clear()
        n.reiniciar_registros()
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual([c for _, c in n.escrituras], [("os", "bucket", "create")] * 2)
        self.assertEqual(set(n.buckets), {b.B_ESTADO, b.B_ARCHIVOS})
        self.assertEqual(n.buckets[b.B_ESTADO]["versioning"], "Enabled")
        self.assertEqual(n.gh_sets, [])

    def test_bucket_de_estado_sin_versionado_solo_activa_el_versionado(self):
        n = Nube()
        self.assertEqual(self.correr(n).codigo, 0)
        n.buckets[b.B_ESTADO]["versioning"] = "Disabled"
        n.reiniciar_registros()
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual([c for _, c in n.escrituras], [("os", "bucket", "update")])
        self.assertEqual(n.buckets[b.B_ESTADO]["versioning"], "Enabled")

    def test_region_del_config_distinta_de_la_de_origen_aborta_con_2(self):
        n = Nube(region="us-phoenix-1")
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.assertIn("región de origen", r.err)
        self.sin_escrituras(n)
        self.assertEqual(self.correr(Nube(region="us-phoenix-1"), "plan").codigo, 2)  # el preflight tambien rige en plan

    def test_usuario_con_tres_llaves_no_genera_otra(self):
        n = Nube()
        n.precargar(comp=True, grupo=True, usuario=True, miembro=True, politica=True, llaves_api=3)
        r = self.correr(n)
        self.assertEqual(n.setup_keys_n, 0)
        self.assertNotIn(("iam", "user", "api-key", "upload"), [c for _, c in n.escrituras])
        self.assertNotIn("OCI_PRIVATE_KEY", n.secretos_gh)
        self.assertNotIn("OCI_FINGERPRINT", n.secretos_gh)
        self.assertIn("3 llaves", " ".join(r.arr.avisos))
        self.assertEqual(r.arr.pruebas["P1"][0], "OMITIDA")
        self.assertEqual(r.arr.pruebas["P5"][0], "OK")  # las llaves S3 si se crearon y se probaron
        self.assertEqual(r.codigo, 1)  # incompleto: sin OCI_PRIVATE_KEY los workflows no pueden correr
        self.assertIn("INCOMPLETO", r.out)
        self.assertNotIn(("variable", "OCI_REGION", REGION), n.gh_sets)  # activaria plan-pruebas con credenciales incompletas
        self.assertIn("No cargo OCI_REGION", r.out)
        self.assertIn(("variable", "OCI_NAMESPACE", NS), n.gh_sets)

    def test_secreto_oci_private_key_existente_no_se_regenera(self):
        n = Nube()
        n.secretos_gh = {"OCI_PRIVATE_KEY": "viejo", "OCI_FINGERPRINT": "aa:bb"}
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual(n.setup_keys_n, 0)
        self.assertNotIn(("iam", "user", "api-key", "upload"), [c for _, c in n.escrituras])
        self.assertEqual(n.secretos_gh["OCI_PRIVATE_KEY"], "viejo")
        self.assertIn("OCI_PRIVATE_KEY: ya existe", r.out)
        self.assertEqual(r.arr.pruebas["P2"][0], "OMITIDA")

    def test_sobrescribir_secretos_permite_reemplazar_el_par(self):
        n = Nube()
        n.secretos_gh = {"OCI_PRIVATE_KEY": "viejo", "OCI_FINGERPRINT": "aa:bb"}
        r = self.correr(n, "apply", "--sobrescribir-secretos")
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual((n.secretos_gh["OCI_PRIVATE_KEY"], n.secretos_gh["OCI_FINGERPRINT"]), (PEM_TECNICO, HUELLA_PUBLICA))

    def test_huella_vieja_sin_privada_en_github_es_conflicto(self):
        n = Nube()
        n.secretos_gh = {"OCI_FINGERPRINT": "aa:bb"}
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.sin_escrituras(n)

    def test_compartimento_deleted_se_ignora_y_se_crea_de_nuevo(self):
        n = Nube()
        n.comps.append({"id": "ocid1.compartment.oc1..viejo", "name": b.N_COMP, "lifecycle-state": "DELETED", "compartment-id": TENANCY})
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertIn("DELETED", r.out)
        self.assertIsNotNone(n.comp_id())
        self.assertNotEqual(n.comp_id(), "ocid1.compartment.oc1..viejo")

    def test_politica_existente_con_otras_sentencias_aborta_sin_crear_nada(self):
        n = Nube()
        n.nuevo("policy", n.politicas, name=b.N_POLITICA, statements=SENTENCIAS_ESPERADAS[:4] + ["Allow group trayecta-go-automatizacion to manage all-resources in tenancy"])
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.assertIn("otras sentencias", r.out + r.err)
        self.assertIn("manage all-resources in tenancy", r.out)  # muestra la diferencia
        self.sin_escrituras(n)  # ni siquiera el compartimento: los conflictos se detectan antes de crear

    def test_politica_con_la_variante_de_respaldo_se_acepta(self):
        n = Nube()
        n.nuevo("policy", n.politicas, name=b.N_POLITICA, statements=list(b.SENTENCIAS_RESPALDO))
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual(r.arr.pruebas["N1"][0], "NO APLICA")
        self.assertNotIn(("iam", "policy", "create"), [c for _, c in n.escrituras])

    def test_p1_falla_con_404_y_se_aplica_la_sentencia_de_respaldo(self):
        n = Nube(p1_requiere_respaldo=True)
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        actualizaciones = [(p, c, o) for p, c, o in n.oci_log if c == ("iam", "policy", "update")]
        self.assertEqual(len(actualizaciones), 1)
        self.assertEqual(json.loads(actualizaciones[0][2]["--statements"]), b.SENTENCIAS_RESPALDO)
        self.assertEqual(actualizaciones[0][2]["--version-date"], "")
        self.assertEqual(n.politica()["statements"], b.SENTENCIAS_RESPALDO)
        self.assertEqual((r.arr.pruebas["P1"][0], r.arr.pruebas["N1"][0], r.arr.pruebas["N12"][0]), ("OK", "NO APLICA", "OK"))
        self.assertTrue(any("respaldo" in h for h in r.arr.hecho))
        self.assertEqual(json.loads((self.dir / "salida" / "resultado.json").read_text(encoding="utf-8"))["politica"]["variante"], "respaldo")

    def test_p1_no_ensancha_la_politica_si_la_politica_ni_siquiera_rige(self):
        n = Nube(no_rige=True)  # todo da 404: P2 tambien falla, asi que el 404 de P1 no prueba que falte la sentencia
        r = self.correr(n)
        self.assertEqual(r.codigo, 1)
        self.assertEqual((r.arr.pruebas["P2"][0], r.arr.pruebas["P1"][0]), ("FALLA", "FALLA"))
        self.assertNotIn(("iam", "policy", "update"), [c for _, c in n.escrituras])
        self.assertEqual(n.gh_sets, [])
        self.assertGreaterEqual(self.dormidos.count(b.PAUSA), b.PROPAGACION)  # espero los 3 minutos de propagacion antes de rendirme

    def test_prueba_obligatoria_que_falla_no_carga_nada_en_github_y_conserva_la_privada(self):
        n = Nube(tecnico_puede=["iam user list"])  # N4 debia ser 404 y el usuario tecnico SI puede listar usuarios
        r = self.correr(n)
        self.assertEqual(r.codigo, 1)
        self.assertEqual(r.arr.pruebas["N4"][0], "FALLA")
        self.assertIn("FALLARON LAS PRUEBAS", r.out)
        self.assertEqual(n.gh_sets, [])
        self.assertEqual(n.secretos_gh, {})
        self.assertTrue((r.arr.tmp / "claves" / "api.pem").is_file(), "la privada se conserva para no perderla")
        self.assertIn(str(r.arr.tmp), r.err)
        # la llave S3 solo se crea si ninguna prueba fallo: no queda nada que borrar a mano en la consola
        self.assertNotIn(("iam", "customer-secret-key", "create"), [c for _, c in n.escrituras])
        self.assertNotIn("llave S3", r.err)
        self.assertEqual(r.arr.pruebas["P5"][0], "OMITIDA")
        self.assertIn(HUELLA_PUBLICA, r.err)  # dice la huella de la llave de API que quedo subida sin su privada en GitHub
        for centinela in CENTINELAS:
            self.assertNotIn(centinela, r.out + r.err)

    def test_p5_s3_falla_si_la_sobrescritura_no_se_lee(self):
        n = Nube()
        original = n.rclone

        def mentiroso(flags, args, entrada, env):
            rc, out, err = original(flags, args, entrada, env)
            return (rc, "humo1", err) if args[0] == "cat" else (rc, out, err)
        n.rclone = mentiroso
        r = self.correr(n)
        self.assertEqual((r.codigo, r.arr.pruebas["P5"][0]), (1, "FALLA"))
        self.assertEqual(n.borrados, [(b.B_ARCHIVOS, "humo/prueba.txt")])  # aun asi limpia el objeto de humo

    def test_propagacion_reintenta_con_la_espera_inyectada(self):
        n = Nube(retraso_tecnico=3, retraso_s3=2)
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertGreaterEqual(self.dormidos.count(b.PAUSA), 3)  # 3 respuestas 401 antes de que la llave rija
        self.assertGreaterEqual(self.dormidos.count(10), 2)  # 2 rechazos de S3 antes de que la llave S3 rija

    def test_llave_de_api_que_rige_a_ratos_no_hace_fallar_las_pruebas_negativas(self):
        # regresion del 2026-11-09: N2 recibio un 401 NotAuthenticated (un nodo de Oracle aun no conocia la llave) cuando esperaba un 404
        n = Nube(tecnico_a_ratos=40)
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        for id_ in ("P1", "P2", "N1", "N2", "N4", "N6", "N7"):
            self.assertEqual(r.arr.pruebas[id_][0], "OK", (id_, r.arr.pruebas[id_]))
        self.assertIn("OCI_PRIVATE_KEY", n.secretos_gh)

    def test_una_negativa_con_401_permanente_falla_tras_reintentar(self):
        # un 401 que no se va nunca no es propagacion: la llave de API no sirve
        n = Nube(tecnico_a_ratos=0)
        original = n.autoriza

        def siempre_401(cmd, o):
            if " ".join(cmd) == "iam user list":
                raise Err(401, "NotAuthenticated")
            return original(cmd, o)
        n.autoriza = siempre_401
        r = self.correr(n)
        self.assertEqual((r.codigo, r.arr.pruebas["N4"][0]), (1, "FALLA"))
        self.assertIn("401", r.arr.pruebas["N4"][1])
        self.assertEqual(n.gh_sets, [])

    def test_s3_que_rige_a_ratos_no_hace_fallar_p5(self):
        # regresion del 2026-11-09: tras el primer acierto, 1 de cada 3 peticiones siguio dando SignatureDoesNotMatch un buen rato,
        # y P5 (que hacia cada operacion una sola vez) fallaba aunque la llave fuera correcta
        n = Nube(retraso_s3=3, s3_a_ratos=40)
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual(r.arr.pruebas["P5"][0], "OK")
        self.assertNotIn("humo/prueba.txt", n.objetos[b.B_ARCHIVOS])  # el objeto de humo queda borrado
        self.assertIn("OCI_S3_ACCESS_KEY", n.secretos_gh)

    def test_s3_que_nunca_rige_agota_una_espera_acotada_y_no_carga_github(self):
        n = Nube(retraso_s3=10_000)
        r = self.correr(n)
        self.assertEqual((r.codigo, r.arr.pruebas["P5"][0]), (1, "FALLA"))
        self.assertEqual(len([e for e in n.linea if e[0] == "rclone"]), b.ESPERA_S3)  # espera acotada: ni un intento mas
        self.assertIn(str(b.ESPERA_S3), r.arr.pruebas["P5"][1])
        self.assertEqual(n.gh_sets, [])

    def test_s3_que_no_ve_el_bucket_falla_enseguida_y_sugiere_el_compartimento_s3(self):
        n = Nube(s3_sin_buckets=True)
        r = self.correr(n)
        self.assertEqual((r.codigo, r.arr.pruebas["P5"][0]), (1, "FALLA"))
        self.assertEqual(len([e for e in n.linea if e[0] == "rclone"]), 1)  # un "no existe" no se arregla esperando
        self.assertIn("compartimento", r.arr.pruebas["P5"][1])

    def test_usuario_que_exige_correo_usa_el_alias_del_administrador(self):
        n = Nube(exige_correo=True)
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        creaciones = [o for _, c, o in n.oci_log if c == ("iam", "user", "create")]
        self.assertEqual(["--email" in o for o in creaciones], [False, True])
        self.assertEqual(creaciones[1]["--email"], CORREO_ALIAS)
        self.assertEqual(n.violaciones, [])

    def test_usuario_que_exige_correo_sin_correo_del_administrador_aborta(self):
        n = Nube(exige_correo=True, correo_admin=None)
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.assertIn("No uso otro correo", r.err)
        self.assertIsNone(n.usuario())  # no se creo el usuario
        self.assertFalse(any("--email" in o for _, c, o in n.oci_log if c == ("iam", "user", "create")))  # ni se intento con otro correo
        self.assertEqual(n.gh_sets, [])

    def test_dominio_de_identidad_en_espanol_reintenta_con_el_alias(self):
        # regresion del 2026-11-09: Oracle respondio 400 IdcsConversionError "Se debe especificar el correo electronico primario"
        # y el reintento solo miraba la palabra "email" en el mensaje
        n = Nube(exige_correo="idcs")
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        creaciones = [o for _, c, o in n.oci_log if c == ("iam", "user", "create")]
        self.assertEqual(["--email" in o for o in creaciones], [False, True])
        self.assertEqual(creaciones[1]["--email"], CORREO_ALIAS)
        self.assertEqual(n.violaciones, [])

    def test_dominio_de_identidad_en_espanol_sin_correo_del_administrador_aborta(self):
        n = Nube(exige_correo="idcs", correo_admin=None)
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.assertIn("No uso otro correo", r.err)
        self.assertIsNone(n.usuario())
        self.assertEqual(n.gh_sets, [])

    def test_n1_prueba_la_lectura_del_tenancy_porque_el_listado_no_comprueba_permisos(self):
        # regresion del 2026-11-09: `iam compartment list` (accessLevel=ANY) responde a cualquier usuario del tenancy, asi que N1 "fallaba" sin motivo
        n = Nube()
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual(r.arr.pruebas["N1"][0], "OK")
        tecnico = [(c, o) for p, c, o in n.oci_log if p == "TECNICO"]
        self.assertIn(("iam", "compartment", "get"), [c for c, _ in tecnico])
        self.assertNotIn(("iam", "compartment", "list"), [c for c, _ in tecnico])

    def test_n1_falla_si_el_tecnico_puede_leer_el_tenancy(self):
        n = Nube(tecnico_puede=["iam compartment get"])  # equivale a un `inspect compartments` sin el filtro request.operation
        r = self.correr(n)
        self.assertEqual((r.codigo, r.arr.pruebas["N1"][0]), (1, "FALLA"))
        self.assertEqual(n.gh_sets, [])

    def test_presupuesto_ajeno_existente_se_reutiliza_sin_crear_otro_ni_tocarlo(self):
        # regresion del 2026-11-09: el tenancy ya tenia 'alerta-trayecta-go' (USD 1, 2 alertas) y crear otro dio 400 LimitExceeded
        n = Nube()
        n.nuevo("budget", n.presupuestos, **{"display-name": "alerta-trayecta-go", "amount": 1.0, "reset-period": "MONTHLY", "alert-rule-count": 2})
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertFalse(any(c[:3] == ("budgets", "budget", "budget") and c[-1] == "create" for _, c in n.escrituras))
        self.assertFalse(any(c[:3] == ("budgets", "budget", "alert-rule") for _, c in n.escrituras))  # ni reglas en el presupuesto ajeno
        self.assertIn("alerta-trayecta-go", r.out)
        self.assertNotIn("LimitExceeded", r.out + r.err)
        resultado = json.loads((self.dir / "salida" / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(resultado["presupuesto"]["nombre"], "alerta-trayecta-go")
        self.assertFalse(resultado["presupuesto"]["propio"])

    def test_presupuesto_que_falla_avisa_y_continua(self):
        n = Nube(presupuestos_falla=True)
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertIn("continúo sin ellos", r.out)
        self.assertFalse(any(c[:3] == ("budgets", "budget", "budget") and c[-1] == "create" for _, c in n.escrituras))
        self.assertEqual(r.arr.pruebas["N7"][0], "OK")

    def test_sin_correo_del_administrador_se_omite_el_presupuesto(self):
        n = Nube(correo_admin=None)
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertFalse(any(c[0] == "budgets" for _, c in n.escrituras))
        self.assertIn("se omite el presupuesto", r.out)

    def test_presupuesto_con_alertas_real_1_por_ciento_y_pronostico_100(self):
        n = Nube()
        self.correr(n)
        reglas = next(iter(n.reglas.values()))
        self.assertEqual([(x["type"], x["threshold"]) for x in reglas], [("ACTUAL", 1.0), ("FORECAST", 100.0)])

    def test_llave_generada_con_cifrado_se_rechaza_y_no_se_sube(self):
        n = Nube(llave_cifrada=True)
        r = self.correr(n)
        self.assertEqual(r.codigo, 1)
        self.assertIn("cifrada", r.err)
        self.assertNotIn(("iam", "user", "api-key", "upload"), [c for _, c in n.escrituras])
        self.assertEqual(n.gh_sets, [])
        self.assertFalse(r.arr.tmp.exists())

    def test_huella_distinta_de_la_calculada_localmente_aborta_antes_de_seguir(self):
        n = Nube(huella_distinta=True)
        r = self.correr(n)
        self.assertEqual(r.codigo, 1)
        self.assertIn("no coincide", r.err)
        self.assertNotIn(("iam", "customer-secret-key", "create"), [c for _, c in n.escrituras])  # no se crea la llave S3 despues
        self.assertEqual(n.gh_sets, [])
        self.assertTrue((r.arr.tmp / "claves" / "api.pem").is_file())  # la privada ya subida se conserva

    def test_limites_de_a1_insuficientes_solo_avisan(self):
        n = Nube(a1=(1, 6))
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual(r.arr.pruebas["P8"][0], "AVISO")
        self.assertIn("P8", r.out)

    def test_bucket_en_otro_compartimento_es_conflicto(self):
        n = Nube()
        n.precargar(comp=True)
        n.buckets[b.B_ARCHIVOS] = {"name": b.B_ARCHIVOS, "compartment-id": "ocid1.compartment.oc1..otro", "public-access-type": "NoPublicAccess",
                                   "storage-tier": "Standard", "versioning": "Disabled"}
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.sin_escrituras(n)

    def test_grupo_con_miembros_ajenos_es_conflicto_antes_de_crear_nada(self):
        n = Nube()
        n.precargar(grupo=True)
        ajeno = n.nuevo("user", n.usuarios, name="otra-persona", email=None, capabilities={})
        n.membresias.add((ajeno["id"], n.grupos[0]["id"]))
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.assertIn("otros miembros", r.out)
        self.assertIn("otra-persona", r.out)
        self.sin_escrituras(n)

    def test_otra_politica_que_nombra_al_grupo_es_conflicto_antes_de_crear_nada(self):
        n = Nube()
        n.nuevo("policy", n.politicas, name="politica-manual", statements=[f"Allow group {b.N_GRUPO} to read all-resources in tenancy"])
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.assertIn("politica-manual", r.out)
        self.sin_escrituras(n)

    def test_politica_de_otro_grupo_con_nombre_parecido_no_es_conflicto(self):
        n = Nube()
        n.nuevo("policy", n.politicas, name="otra", statements=[f"Allow group {b.N_GRUPO}-extra to read all-resources in tenancy"])
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertFalse(b.nombra_grupo(f"Allow group {b.N_GRUPO}-extra to x"))
        self.assertTrue(b.nombra_grupo(f"Allow group '{b.N_GRUPO}' to x") and b.nombra_grupo(f"Allow group Default/{b.N_GRUPO} to x"))

    def test_una_denegacion_403_tambien_cuenta_como_negativa_superada(self):
        n = Nube(deniega_403=["budgets budget budget list"])
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual(r.arr.pruebas["N7"][0], "OK")
        self.assertIn("403", r.arr.pruebas["N7"][1])

    def test_si_docker_no_puede_correr_rclone_no_se_reintenta(self):
        n = Nube(rclone_docker_falla=True)
        r = self.correr(n)
        self.assertEqual((r.codigo, r.arr.pruebas["P5"][0]), (1, "FALLA"))
        self.assertIn("125", r.arr.pruebas["P5"][1])
        self.assertEqual(self.dormidos.count(10), 0)
        self.assertEqual(len([e for e in n.linea if e[0] == "rclone"]), 1)
        self.assertEqual(n.gh_sets, [])

    def test_bucket_publico_es_conflicto(self):
        n = Nube()
        n.precargar(comp=True, buckets=True)
        n.buckets[b.B_ESTADO]["public-access-type"] = "ObjectRead"
        self.assertEqual(self.correr(n).codigo, 2)
        self.sin_escrituras(n)

    def test_llave_s3_existente_sin_secretos_en_github_avisa_y_queda_incompleto(self):
        n = Nube()
        n.precargar(comp=True, grupo=True, usuario=True, miembro=True, politica=True, s3=True)
        r = self.correr(n)
        self.assertEqual(r.codigo, 1)
        self.assertIn("bórrala en la consola", " ".join(r.arr.avisos))
        self.assertNotIn(("iam", "customer-secret-key", "create"), [c for _, c in n.escrituras])
        self.assertIn("OCI_S3_SECRET_KEY", r.out)

    def test_variable_existente_con_otro_valor_no_se_sobrescribe(self):
        n = Nube()
        n.variables_gh = {"OCI_REGION": "us-phoenix-1"}
        r = self.correr(n)
        self.assertEqual(n.variables_gh["OCI_REGION"], "us-phoenix-1")
        self.assertIn("OCI_REGION", " ".join(r.arr.avisos))
        self.assertEqual(r.codigo, 0, r.out + r.err)

    def test_gh_sin_sesion_aborta_apply_y_plan_lo_reporta(self):
        n = Nube(gh_autenticado=False)
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.sin_escrituras(n)
        p = self.correr(Nube(gh_autenticado=False), "plan")
        self.assertEqual(p.codigo, 0)
        self.assertIn("gh auth login", p.out)


class NubeNegativaRara(Nube):
    """El usuario tecnico recibe un error que NO es una denegacion en la prueba negativa N4 (listar usuarios)."""

    def __init__(self, error, **kw):
        super().__init__(**kw)
        self.error = error

    def autoriza(self, cmd, o):
        if " ".join(cmd) == "iam user list":
            raise self.error
        super().autoriza(cmd, o)


class NubeGhFalla(Nube):
    """gh no puede guardar un secreto concreto (permisos del token, red)."""

    def __init__(self, secreto, **kw):
        super().__init__(**kw)
        self.secreto = secreto

    def gh(self, args, entrada):
        if args[:3] == ["secret", "set", self.secreto]:
            self.linea.append(("gh", tuple(args[:2])))
            return 1, "", "HTTP 403: Resource not accessible by personal access token"
        return super().gh(args, entrada)


class NubeUsuarioLento(Nube):
    """Oracle deja al usuario recien creado en CREATING durante dos lecturas."""

    def h_iam_user_create(self, o):
        u = super().h_iam_user_create(o)
        u["lifecycle-state"], self.get_restantes[u["id"]] = "CREATING", 2
        return dict(u)

    def h_iam_user_get(self, o):
        u = next((x for x in self.usuarios if x["id"] == o["--user-id"]), None)
        if u and self.get_restantes.get(u["id"], 0) > 0:
            self.get_restantes[u["id"]] -= 1
            return dict(u)
        if u and u["lifecycle-state"] == "CREATING":
            u["lifecycle-state"] = "ACTIVE"
        return super().h_iam_user_get(o)


class PruebasRevision(Base):
    """Casos que la revision adversarial encontro sin cubrir (ver revision.md)."""

    def arranque(self, respuestas):
        guion = Guion(respuestas)
        a = b.Arranque(b.crear_parser().parse_args(["plan", "--config", "c", "--clave-admin", "k"]), guion, self.dormidos.append)
        a.tmp, a.clave_admin = self.dir, self.pem
        return a, guion

    def test_la_imagen_del_cli_esta_fijada_por_digest(self):
        self.assertIn("@sha256:", b.IMAGEN_OCI)
        self.assertNotIn(":latest", b.IMAGEN_OCI)

    def test_una_negativa_con_500_401_o_404_de_otro_codigo_no_cuenta_como_denegada(self):
        for error in (Err(500, "InternalServerError"), Err(401, "NotAuthenticated"), Err(404, "BucketNotFound")):
            with self.subTest(error.codigo):
                n = NubeNegativaRara(error)
                r = self.correr(n)
                self.assertEqual((r.codigo, r.arr.pruebas["N4"][0]), (1, "FALLA"))
                self.assertEqual(n.gh_sets, [])

    def test_omitir_una_negativa_la_deja_como_omitida_y_carga_github(self):
        sin = self.correr(Nube(tecnico_puede=["budgets budget budget list"]))  # N7 debia ser 404 y el tecnico SI puede listar presupuestos
        self.assertEqual((sin.codigo, sin.arr.pruebas["N7"][0]), (1, "FALLA"))
        n = Nube(tecnico_puede=["budgets budget budget list"])
        r = self.correr(n, "apply", "--omitir-prueba", "N7")
        self.assertEqual((r.codigo, r.arr.pruebas["N7"][0]), (0, "OMITIDA"), r.out + r.err)
        self.assertEqual({x[1] for x in n.gh_sets if x[0] == "secret"}, set(b.SECRETOS_GH))
        res = json.loads((self.dir / "salida" / "resultado.json").read_text(encoding="utf-8"))
        self.assertEqual(res["pruebas"]["N7"]["estado"], "OMITIDA")

    def test_omitir_prueba_solo_acepta_negativas(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            b.crear_parser().parse_args(["apply", "--config", "c", "--clave-admin", "k", "--omitir-prueba", "P1"])

    def test_compartimento_creating_pide_esperar_y_no_escribe(self):
        n = Nube()
        n.comps.append({"id": "ocid1.compartment.oc1..nuevo", "name": b.N_COMP, "lifecycle-state": "CREATING", "compartment-id": TENANCY})
        r = self.correr(n)
        self.assertEqual(r.codigo, 2)
        self.assertIn("todavía se está creando", r.out + r.err)
        self.sin_escrituras(n)

    def test_la_busqueda_por_nombre_no_distingue_mayusculas(self):
        n = Nube()
        n.nuevo("compartment", n.comps, name=b.N_COMP.upper(), **{"compartment-id": TENANCY})
        r = self.correr(n, "plan")
        self.assertEqual(r.codigo, 0)
        self.assertIsNotNone(r.arr.comp)
        self.assertNotIn("crear bajo el tenancy", r.out)

    def test_dos_llaves_s3_ajenas_no_dejan_crear_otra(self):
        n = Nube()
        n.precargar(comp=True, grupo=True, usuario=True, miembro=True, politica=True)
        n.llaves_s3[n.usuario()["id"]] = [{"display-name": f"otra{i}", "id": f"a{i}", "lifecycle-state": "ACTIVE"} for i in (1, 2)]
        r = self.correr(n)
        self.assertFalse(r.arr.crear_s3)
        self.assertNotIn(("iam", "customer-secret-key", "create"), [c for _, c in n.escrituras])

    def test_gh_que_falla_al_guardar_un_secreto_termina_con_1_y_avisa(self):
        n = NubeGhFalla("OCI_S3_ACCESS_KEY")
        r = self.correr(n)
        self.assertEqual(r.codigo, 1)
        self.assertIn("OCI_S3_ACCESS_KEY", r.err)
        self.assertIn("llave S3", r.err)  # el secreto S3 no llego a GitHub y no se puede releer
        self.assertIn("Hecho hasta aquí", r.err)
        self.assertTrue(r.arr.tmp.exists(), "la privada temporal se conserva")
        self.assertNotIn(("variable", "OCI_REGION", REGION), n.gh_sets)
        for centinela in CENTINELAS:
            self.assertNotIn(centinela, r.out + r.err)

    def test_usuario_nuevo_espera_a_estar_activo(self):
        n = NubeUsuarioLento()
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        cmds = [c for _, c, _ in n.oci_log]
        i, j = cmds.index(("iam", "user", "create")), cmds.index(("iam", "user", "update-user-capabilities"))
        self.assertGreaterEqual(cmds[i:j].count(("iam", "user", "get")), 3)

    def test_error_de_uso_del_cli_sale_por_stdout_y_se_muestra_con_el_comando(self):
        a, _ = self.arranque([(2, "Usage: oci iam policy update [OPTIONS]\n\nError: Missing option --version-date.\n", "")])
        with self.assertRaises(b.ErrorOCI) as c:
            a.oci(["iam", "policy", "update", "--policy-id", "X"])
        self.assertIn("iam policy update", str(c.exception))
        self.assertIn("--version-date", str(c.exception))

    def test_salida_en_una_carpeta_ajena_no_pisa_su_gitignore(self):
        salida = self.dir / "salida"
        salida.mkdir()
        (salida / ".gitignore").write_text("mio\n", encoding="utf-8")
        (salida / "otro.txt").write_text("x", encoding="utf-8")
        r = self.correr(Nube())
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.assertEqual((salida / ".gitignore").read_text(encoding="utf-8"), "mio\n")
        self.assertTrue((salida / "resultado.json").is_file())

    def test_llave_de_api_previa_del_usuario_tecnico_se_avisa(self):
        n = Nube()
        n.precargar(comp=True, grupo=True, usuario=True, miembro=True, politica=True, llaves_api=1)
        r = self.correr(n)
        self.assertIn("aa:00", " ".join(r.arr.avisos))


class PruebasPlan(Base):
    def test_plan_no_llama_a_create_upload_update_ni_add(self):
        n = Nube()
        r = self.correr(n, "plan")
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.sin_escrituras(n)
        self.assertFalse(any(c[-1] in Nube.ESCRITURA for _, c, _ in n.oci_log))
        self.assertFalse(any(e[0] == "rclone" for e in n.linea))
        self.assertIn("no se creó ni se modificó nada", r.out)
        for fragmento in ("Recurso", "Estado actual", "Acción", f"Compartimento {b.N_COMP}", "no existe", "crear bajo el tenancy",
                          "generar par RSA 2048", f"Bucket {b.B_ESTADO}", "versionado"):
            self.assertIn(fragmento, r.out)
        self.assertFalse(r.arr.tmp.exists())

    def test_plan_sobre_una_nube_ya_aprovisionada_no_propone_acciones(self):
        n = Nube()
        self.assertEqual(self.correr(n).codigo, 0)
        n.reiniciar_registros()
        r = self.correr(n, "plan")
        self.assertEqual(r.codigo, 0)
        self.sin_escrituras(n)
        self.assertNotIn("crear", "\n".join(l for l in r.out.splitlines() if l.startswith(("Compartimento", "Grupo", "Usuario", "Política", "Bucket"))))

    def test_plan_reporta_conflictos_y_termina_con_0(self):
        n = Nube()
        n.comps.append({"id": "ocid1.compartment.oc1..viejo", "name": b.N_COMP, "lifecycle-state": "DELETING", "compartment-id": TENANCY})
        r = self.correr(n, "plan")
        self.assertEqual(r.codigo, 0)
        self.assertIn("CONFLICTO", r.out)
        self.assertIn("DELETING", r.out)
        self.sin_escrituras(n)


class PruebasSecretos(Base):
    def revisar(self, r, n):
        for centinela in CENTINELAS:
            self.assertNotIn(centinela, r.out, centinela)
            self.assertNotIn(centinela, r.err, centinela)
            for argv, _ in n.llamadas:
                self.assertNotIn(centinela, " ".join(argv), f"{centinela} en argv: {argv[:3]}")
        self.assertNotIn("BEGIN PRIVATE KEY", r.out + r.err)
        for _, entrada in n.llamadas:
            self.assertNotIn("SENTINELA_PEM_ADMIN", entrada or "")

    def test_ningun_secreto_en_stdout_stderr_argv_ni_resultado(self):
        n = Nube()
        r = self.correr(n)
        self.assertEqual(r.codigo, 0, r.out + r.err)
        self.revisar(r, n)
        resultado = (self.dir / "salida" / "resultado.json").read_text(encoding="utf-8")
        for centinela in CENTINELAS:
            self.assertNotIn(centinela, resultado)
        # gh recibio los valores por stdin; el argv de gh no lleva valores
        for argv, entrada in n.llamadas:
            if argv[:3] == ["gh", "secret", "set"]:
                self.assertEqual(len(argv), 6, argv)  # gh secret set NOMBRE --repo R: el valor no va en argv
                self.assertTrue(entrada)
        stdin_gh = {x[1]: x[2] for x in n.gh_sets if x[0] == "secret"}
        self.assertEqual(stdin_gh["OCI_PRIVATE_KEY"], PEM_TECNICO)
        self.assertEqual(stdin_gh["OCI_S3_SECRET_KEY"], SECRETO_S3)
        # rclone: las llaves S3 viajaron por el entorno del subproceso, jamas en argv
        self.assertTrue(n.env_rclone)
        self.assertTrue(all(e.get("RCLONE_CONFIG_OCI_SECRET_ACCESS_KEY") == SECRETO_S3 for e in n.env_rclone))
        self.assertEqual(n.violaciones, [])

    def test_error_de_un_comando_sensible_no_filtra_el_mensaje(self):
        n = Nube(fallo_s3_create=True)  # el mensaje de error de Oracle trae el centinela del secreto
        r = self.correr(n)
        self.assertEqual(r.codigo, 1)
        self.revisar(r, n)
        self.assertIn("ERROR (1)", r.err)

    def test_si_la_salida_de_error_trae_una_privada_se_redacta(self):
        a = b.Arranque(b.crear_parser().parse_args(["plan", "--config", "c", "--clave-admin", "k"]))
        a.secretos.add("VALOR_SECRETO")
        self.assertEqual(a.limpiar("x VALOR_SECRETO y"), "x *** y")
        self.assertNotIn("SENTINELA", a.limpiar(PEM_TECNICO))


class PruebasOCI(Base):
    def arranque(self, respuestas):
        guion = Guion(respuestas)
        a = b.Arranque(b.crear_parser().parse_args(["plan", "--config", "c", "--clave-admin", "k"]), guion, self.dormidos.append)
        a.tmp, a.clave_admin = self.dir, self.pem
        return a, guion

    def test_forma_del_comando_docker(self):
        a, g = self.arranque([(0, '{"data": []}', ""), (0, '{"data": []}', "")])
        a.oci(["iam", "user", "list", "-c", "T"])
        a.oci(["iam", "user", "list", "-c", "T"], perfil="TECNICO")
        admin, tecnico = g.llamadas
        for cmd in (admin, tecnico):
            self.assertEqual(cmd[:3], ["docker", "run", "--rm"])
            self.assertNotIn("--privileged", cmd)
            self.assertIn("OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True", cmd)
            self.assertIn("SUPPRESS_LABEL_WARNING=True", cmd)
            i = cmd.index(b.IMAGEN_OCI)
            self.assertEqual(cmd[i + 1:i + 9], ["--config-file", "/cfg/config", "--profile", cmd[i + 4], "--output", "json", "--auth", "api_key"])
            montajes = [cmd[j + 1] for j, x in enumerate(cmd) if x == "--mount"]
            self.assertTrue(montajes and all(m.endswith(",readonly") for m in montajes), montajes)
        self.assertEqual(admin[admin.index(b.IMAGEN_OCI) + 4], "DEFAULT")
        self.assertTrue(any("target=/claves/admin.pem" in x for x in admin))
        self.assertEqual(tecnico[tecnico.index(b.IMAGEN_OCI) + 4], "TECNICO")
        self.assertFalse(any("admin.pem" in x for x in tecnico), "el perfil tecnico no monta la llave del administrador")
        self.assertTrue(any("target=/claves-tecnico" in x for x in tecnico))
        self.assertEqual(admin[admin.index(b.IMAGEN_OCI) + 9:], ["iam", "user", "list", "-c", "T"])

    def test_salida_vacia_devuelve_none(self):
        a, _ = self.arranque([(0, "  \n", "")])
        self.assertIsNone(a.oci(["iam", "user", "list"]))

    def test_reintenta_429_y_5xx_con_espera(self):
        a, g = self.arranque([error_servicio(429), error_servicio(503), (0, '{"data": [1]}', "")])
        self.assertEqual(a.oci(["x"]), {"data": [1]})
        self.assertEqual(len(g.llamadas), 3)
        self.assertEqual(self.dormidos, [5, 10])

    def test_se_rinde_tras_seis_intentos(self):
        a, g = self.arranque([error_servicio(503, "ServiceUnavailable")] * 6)
        with self.assertRaises(b.ErrorOCI) as c:
            a.oci(["x"])
        self.assertEqual((c.exception.estado, c.exception.codigo), (503, "ServiceUnavailable"))
        self.assertEqual(len(g.llamadas), 6)

    def test_no_reintenta_un_404_salvo_que_se_pida(self):
        a, g = self.arranque([error_servicio(404, "NotAuthorizedOrNotFound")])
        with self.assertRaises(b.ErrorOCI) as c:
            a.oci(["x"])
        self.assertEqual((c.exception.estado, c.exception.codigo), (404, "NotAuthorizedOrNotFound"))
        self.assertEqual((len(g.llamadas), self.dormidos), (1, []))
        a, g = self.arranque([error_servicio(404), (0, '{"data": 1}', "")])
        self.assertEqual(a.oci(["x"], reintentar_404=True), {"data": 1})
        self.assertEqual(len(g.llamadas), 2)

    def test_error_de_red_sin_json_es_transitorio(self):
        a, g = self.arranque([(1, "", "ConnectTimeout: Max retries exceeded"), (-1, "", "tiempo de espera agotado"), (0, "{}", "")])
        self.assertEqual(a.oci(["x"]), {})
        self.assertEqual(len(g.llamadas), 3)

    def test_comando_sensible_no_devuelve_el_mensaje_de_error(self):
        a, _ = self.arranque([error_servicio(400, "InvalidParameter", "contiene SENTINELA_SECRETO_S3")])
        with self.assertRaises(b.ErrorOCI) as c:
            a.oci(["iam", "customer-secret-key", "create"], sensible=True)
        self.assertNotIn("SENTINELA", str(c.exception))
        a, _ = self.arranque([error_servicio(400, "InvalidParameter", "mensaje normal")])
        with self.assertRaises(b.ErrorOCI) as c:
            a.oci(["x"])
        self.assertIn("mensaje normal", str(c.exception))

    def test_salida_que_no_es_json_no_se_muestra(self):
        a, _ = self.arranque([(0, "SENTINELA_SECRETO_S3 no es json", "")])
        with self.assertRaises(b.ErrorOCI) as c:
            a.oci(["x"])
        self.assertNotIn("SENTINELA", str(c.exception))

    def test_config_o_llave_invalidos_son_una_precondicion_sin_reintentos(self):
        a, g = self.arranque([(1, "", ERROR_CONFIG_REAL)])
        with self.assertRaises(b.ErrorPrecondicion) as c:
            a.oci(["x"])
        self.assertIn("fingerprint malformed", str(c.exception))
        self.assertEqual((len(g.llamadas), self.dormidos), (1, []))

    def test_docker_caido_es_una_precondicion(self):
        a, _ = self.arranque([(1, "", "error during connect: open //./pipe/dockerDesktopLinuxEngine")])
        with self.assertRaises(b.ErrorPrecondicion):
            a.oci(["x"])
        a, _ = self.arranque([(125, "", "docker: Error response from daemon: pull access denied")])
        with self.assertRaises(b.ErrorPrecondicion):
            a.oci(["x"])

    def test_rclone_lleva_las_llaves_por_entorno_y_no_por_argv(self):
        a, g = self.arranque([(0, "", "")])
        a.s3, a.ns, a.region = ("VALOR_ACC_123", "VALOR_SEC_456"), NS, REGION
        envs = []
        original = g.__call__

        def espia(argv, entrada=None, env=None, timeout=None):
            envs.append(env)
            return original(argv, entrada, env, timeout)
        a.ejecutar = espia
        a.rclone(["rcat", "oci:b/p"], "humo1")
        cmd = g.llamadas[0]
        self.assertNotIn("VALOR_SEC_456", " ".join(cmd))
        self.assertNotIn("VALOR_ACC_123", " ".join(cmd))
        self.assertIn("RCLONE_CONFIG_OCI_SECRET_ACCESS_KEY", cmd)
        self.assertEqual((envs[0]["RCLONE_CONFIG_OCI_ACCESS_KEY_ID"], envs[0]["RCLONE_CONFIG_OCI_SECRET_ACCESS_KEY"]),
                         ("VALOR_ACC_123", "VALOR_SEC_456"))
        self.assertIn("-i", cmd)
        self.assertNotIn("--privileged", cmd)
        self.assertIn(b.IMAGEN_RCLONE, cmd)


class PruebasEjecutorReal(unittest.TestCase):
    """`ejecutar_real` es el unico lugar con subprocesos: se prueba con el propio interprete, sin Docker ni red."""

    def correr(self, codigo, **kw):
        return b.ejecutar_real([sys.executable, "-I", "-c", codigo], **kw)

    def test_la_entrada_viaja_en_bytes_exactos_sin_crlf(self):
        rc, out, err = self.correr("import sys; sys.stdout.write(repr(sys.stdin.buffer.read())); sys.stderr.write('e')", entrada="N/A\nN/A\n")
        self.assertEqual((rc, out, err), (0, repr(b"N/A\nN/A\n"), "e"))  # en Windows el modo texto la volveria N/A\r\nN/A\r\n

    def test_sin_entrada_el_stdin_queda_cerrado(self):
        rc, out, _ = self.correr("import sys; sys.stdout.write(repr(sys.stdin.read()))")
        self.assertEqual((rc, out), (0, "''"))

    def test_codigo_de_salida_y_decodificacion_utf8(self):
        rc, out, _ = self.correr("import sys; sys.stdout.buffer.write('región'.encode()); sys.exit(3)")
        self.assertEqual((rc, out), (3, "región"))

    def test_el_entorno_se_pasa_al_subproceso(self):
        rc, out, _ = self.correr("import os; print(os.environ['PRUEBA_X'], end='')", env={**os.environ, "PRUEBA_X": "valor"})
        self.assertEqual((rc, out), (0, "valor"))

    def test_programa_inexistente_es_una_precondicion(self):
        with self.assertRaises(b.ErrorPrecondicion):
            b.ejecutar_real(["programa-que-no-existe-xyz"])

    def test_tiempo_agotado_devuelve_menos_uno(self):
        self.assertEqual(self.correr("import time; time.sleep(30)", timeout=0.5)[0], -1)


class PruebasUtilidades(Base):
    def test_huella_md5_coincide_con_openssl(self):
        self.assertEqual(b.huella_md5(PUBLICA), HUELLA_PUBLICA)

    def test_correo_derivado_con_alias(self):
        self.assertEqual(b.correo_derivado("juan@example.com"), "juan+claude-code-deployer@example.com")
        self.assertEqual(b.correo_derivado("juan+otro@example.com"), "juan+claude-code-deployer@example.com")

    def test_desviaciones_de_capacidades(self):
        ok = {k: k in b.CAPACIDADES for k in CAPS_TODAS}
        self.assertEqual(b.desviaciones(ok), [])
        self.assertEqual(b.desviaciones({**ok, "can-use-console-password": True}), ["can-use-console-password"])
        self.assertEqual(b.desviaciones({**ok, "can-use-api-keys": False}), ["can-use-api-keys"])
        self.assertEqual(b.desviaciones(None), sorted(b.CAPACIDADES))

    def test_analizar_error(self):
        self.assertEqual(b.analizar_error(error_servicio(404, "NotAuthorizedOrNotFound", "no")[2]), (404, "NotAuthorizedOrNotFound", "no"))
        self.assertEqual(b.analizar_error("boom\nultima linea"), (None, None, "boom ; ultima linea"))
        self.assertEqual(b.analizar_error(None), (None, None, ""))
        # salida real del OCI CLI 3.96.0 con un config invalido: texto y tabla ASCII, sin JSON
        estado, codigo, resumen = b.analizar_error(ERROR_CONFIG_REAL)
        self.assertEqual((estado, codigo), (None, None))
        self.assertIn("The config file at /cfg/config is invalid", resumen)
        self.assertIn("fingerprint malformed", resumen)
        self.assertNotIn("Warning:", resumen)
        self.assertNotIn("+--", resumen)

    def test_str_de_errores(self):
        self.assertEqual(str(b.ErrorOCI(404, "NotAuthorizedOrNotFound", "no")), "HTTP 404 NotAuthorizedOrNotFound: no")
        self.assertEqual(str(b.ErrorOCI(None, None, "solo el mensaje")), "solo el mensaje")

    def arranque_config(self, texto=CONFIG):
        self.config.write_text(texto, encoding="utf-8")
        return b.Arranque(b.crear_parser().parse_args(["plan", "--config", str(self.config), "--clave-admin", str(self.pem)]))

    def test_config_pegado_de_la_consola_con_comentario_y_key_file_de_ejemplo(self):
        a = self.arranque_config("﻿" + CONFIG)  # incluso con BOM
        a.leer_config()
        self.assertEqual((a.T, a.region, a.cfg["user"]), (TENANCY, REGION, ADMIN))
        a.tmp = self.dir
        (self.dir / "cfg").mkdir()
        a.escribir_config()
        texto = (self.dir / "cfg" / "config").read_text(encoding="utf-8")
        self.assertIn("key_file=/claves/admin.pem", texto)
        self.assertNotIn("<path to your private keyfile>", texto)
        self.assertNotIn("TECNICO", texto)
        a.usr, a.huella = {"id": "ocid1.user.oc1..tec"}, HUELLA_PUBLICA
        a.escribir_config()
        texto = (self.dir / "cfg" / "config").read_text(encoding="utf-8")
        self.assertIn("[TECNICO]\nuser=ocid1.user.oc1..tec", texto)
        self.assertIn("key_file=/claves-tecnico/api.pem", texto)
        for centinela in CENTINELAS:
            self.assertNotIn(centinela, texto)

    def test_config_invalido_aborta(self):
        for texto in (CONFIG.replace(f"region={REGION}\n", ""), CONFIG + "pass_phrase=secreto\n", "sin cabecera\nuser=x\n"):
            with self.assertRaises(b.ErrorPrecondicion):
                self.arranque_config(texto).leer_config()

    def test_llave_del_administrador_invalida_aborta(self):
        a = self.arranque_config()
        for contenido in ("-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n", "no es una llave\n"):
            self.pem.write_text(contenido, encoding="utf-8")
            with self.assertRaises(b.ErrorPrecondicion):
                a.leer_config()
        a.a.clave_admin = str(self.dir / "no-existe.pem")
        with self.assertRaises(b.ErrorPrecondicion):
            a.leer_config()

    def test_ayuda_de_los_subcomandos(self):
        for argv, esperado in ((["--help"], "plan"), (["plan", "--help"], "--clave-admin"), (["apply", "--help"], "--sobrescribir-secretos")):
            salida = io.StringIO()
            with contextlib.redirect_stdout(salida), self.assertRaises(SystemExit) as c:
                b.crear_parser().parse_args(argv)
            self.assertEqual(c.exception.code, 0)
            self.assertIn(esperado, salida.getvalue())

    def test_main_entrega_el_codigo_de_salida(self):
        n = Nube(region="us-phoenix-1")
        argv = ["plan", "--config", str(self.config), "--clave-admin", str(self.pem)]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(b.main(argv, ejecutar=n, dormir=self.dormidos.append), 2)


if __name__ == "__main__":
    unittest.main()
