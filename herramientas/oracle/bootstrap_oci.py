#!/usr/bin/env python3
"""Arranque unico de Oracle Cloud para Trayecta Go (entorno `pruebas`).

Crea lo que hoy se haria a mano en la consola: compartimento, grupo, usuario tecnico, politica,
llave de API, Customer Secret Key, buckets y presupuesto; verifica los permisos con pruebas
positivas y negativas y, solo si todo pasa, carga los secretos en GitHub. Usa el OCI CLI
oficial en contenedor (Docker). NO ejecuta `tofu apply`: eso lo hace el workflow desplegar-pruebas.

  python -I bootstrap_oci.py plan  --config CONFIG_OCI --clave-admin ADMIN.pem
  python -I bootstrap_oci.py apply --config CONFIG_OCI --clave-admin ADMIN.pem [--sobrescribir-secretos]

Requisitos: Docker Desktop (imagen del OCI CLI 3.96.0 fijada por digest), gh con sesion iniciada y Python 3.12 (solo biblioteca estandar).
No elimina ningun recurso de Oracle: lo unico que borra es el objeto de humo que la prueba S3 crea ella misma.

Codigos de salida: 0 exito; 1 error, prueba fallida o resultado incompleto; 2 aborto de seguridad o precondicion.
"""
import argparse
import base64
import configparser
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

IMAGEN_OCI = "ghcr.io/oracle/oci-cli@sha256:9ecc89fffd09be2c9e1039132112f18b2ca1c9bf09bf01744070c1c42f6d848b"  # 3.96.0, la validada
IMAGEN_RCLONE = "rclone/rclone:1.75.2"  # la misma de entornos/pruebas/compose/compose.yaml
REPO_INFRA = "FernandoMartinez018/trayecta-go-infra"

N_COMP, N_GRUPO, N_USUARIO = "trayecta-go-pruebas", "trayecta-go-automatizacion", "claude-code-deployer"
N_POLITICA, N_LLAVE_S3, N_PRESUPUESTO = "trayecta-go-automatizacion-pruebas", "trayecta-go-s3", "trayecta-go-presupuesto"
B_ESTADO, B_ARCHIVOS = "trayecta-go-tofu-estado", "trayecta-go-pruebas-archivos"
TAGS = json.dumps({"proyecto": "trayecta-go", "entorno": "pruebas", "gestionado-por": "opentofu", "creado-por": "bootstrap-oci"})

SENT_BASE = [f"Allow group {N_GRUPO} to manage {fam} in compartment {N_COMP}"
             for fam in ("instance-family", "virtual-network-family", "volume-family", "object-family")]
SENTENCIAS = SENT_BASE + [f"Allow group {N_GRUPO} to inspect compartments in tenancy where request.operation='ListAvailabilityDomains'"]
SENTENCIAS_RESPALDO = SENT_BASE + [f"Allow group {N_GRUPO} to inspect compartments in tenancy"]
CAPACIDADES = {"can-use-api-keys", "can-use-customer-secret-keys"}  # las unicas que quedan en true
REGLAS = [("ACTUAL", 1, "trayecta-go-gasto-real-1pct"), ("FORECAST", 100, "trayecta-go-pronostico-100pct")]
SECRETOS_GH = ["OCI_TENANCY_OCID", "OCI_USER_OCID", "OCI_FINGERPRINT", "OCI_PRIVATE_KEY",
               "OCI_COMPARTMENT_OCID", "OCI_S3_ACCESS_KEY", "OCI_S3_SECRET_KEY"]
VARIABLES_GH = ["OCI_NAMESPACE", "OCI_REGION"]  # OCI_REGION al final: activa el workflow plan-pruebas
PROPAGACION, PAUSA = 36, 5  # 36 reintentos de 5 s = 3 minutos para que Oracle propague llaves y politicas
# Llave S3 (medido el 2026-11-09): falla ~1 min, luego acierta a ratos mientras los nodos de Oracle se ponen al dia, y la primera llave de
# un usuario tardo mas de 3 min. P5 espera hasta 90 intentos de 10 s (~20 min), exige 3 listados seguidos y reintenta cada operacion 6 veces.
ESPERA_S3, ESTABLE_S3, REINTENTOS_S3, PAUSA_S3 = 90, 3, 6, 10
REINTENTOS_401 = 12  # una prueba negativa reintenta un 401 hasta 12 veces de 5 s: la llave de API tambien se propaga por nodos
TRANSITORIOS = (429, 500, 502, 503, 504)
RED = re.compile(r"timed out|timeout|connection (reset|aborted|refused)|max retries exceeded|temporary failure|name resolution", re.I)
CONFIG_MALO = re.compile(r"config file at .* is invalid|Profile '.*' not found|InvalidPrivateKey|private key", re.I)  # errores locales del CLI


class ErrorPrecondicion(Exception):
    """Aborto de seguridad o precondicion que no se cumple (codigo de salida 2)."""


class ErrorOCI(Exception):
    def __init__(self, estado, codigo, mensaje, cmd=None):
        base = f"HTTP {estado} {codigo}: {mensaje}" if estado else (mensaje or "error del OCI CLI")
        super().__init__(f"[{cmd}] {base}" if cmd else base)
        self.estado, self.codigo, self.mensaje = estado, codigo, mensaje


def lista(r):
    return (r or {}).get("data") or []


def dato(r):
    return (r or {}).get("data")


def huella_md5(pem_publica):
    """Huella de OCI: MD5 del DER de la llave publica, en pares hexadecimales separados por dos puntos."""
    der = base64.b64decode("".join(l for l in pem_publica.splitlines() if l and not l.startswith("-----")))
    h = hashlib.md5(der, usedforsecurity=False).hexdigest()
    return ":".join(h[i:i + 2] for i in range(0, 32, 2))


def nombra_grupo(sentencia):
    """True si la sentencia nombra al grupo tecnico (el nombre exacto, no otro que lo contenga)."""
    return re.search(rf"(?<![\w-]){re.escape(N_GRUPO)}(?![\w-])", sentencia) is not None


CORREO_EXIGIDO = re.compile(r"e-?mail|correo", re.I)  # Oracle responde en el idioma del usuario: "correo electrónico primario"


def endpoint_s3(ns, region):
    """Endpoint path-style de la API compatible con S3: el mismo que usan los workflows y Ansible de trayecta-go-infra, para que P5 pruebe lo
    que usará producción. Medido el 2026-11-09: este dominio y oci.customer-oci.com se comportan igual; los fallos eran de propagación."""
    return f"https://{ns}.compat.objectstorage.{region}.oraclecloud.com"


def correo_derivado(correo):
    """Alias +claude-code-deployer sobre el correo del administrador (nunca se usa otro correo)."""
    usuario, dominio = correo.split("@", 1)
    return f"{usuario.split('+')[0]}+{N_USUARIO}@{dominio}"


def desviaciones(capacidades):
    """Capacidades que no estan como se espera: solo API keys y Customer Secret Keys en true."""
    c = capacidades or {}
    return sorted(k for k in CAPACIDADES | set(c) if bool(c.get(k)) != (k in CAPACIDADES))


def analizar_error(err):
    """Extrae (estado, codigo, mensaje) del JSON `ServiceError` que imprime el OCI CLI; nunca devuelve el texto crudo."""
    d = {}
    m = re.search(r"\{.*\}", err or "", re.S)
    if m:
        try:
            d = json.loads(m.group(0))
        except ValueError:
            d = {}
    d = d if isinstance(d, dict) else {}
    # sin JSON (config invalido, red...) el CLI imprime texto y tablas ASCII: resumo las primeras lineas utiles
    lineas = [" ".join(re.sub(r"[+\-=]{3,}", " ", l).replace("|", " ").split()) for l in (err or "").splitlines()]
    resumen = " ; ".join([l for l in lineas if l and not l.startswith("Warning:")][:4])
    estado = d.get("status")
    return (estado if isinstance(estado, int) else None), d.get("code"), str(d.get("message") or resumen)[:300]


def ejecutar_real(argv, entrada=None, env=None, timeout=600):
    """Unico lugar que lanza subprocesos. La entrada viaja en bytes: en Windows el modo texto cambia \\n por \\r\\n."""
    kw = {"stdin": subprocess.DEVNULL} if entrada is None else {"input": entrada.encode("utf-8")}
    try:
        p = subprocess.run(argv, capture_output=True, env=env, timeout=timeout, **kw)
    except FileNotFoundError:
        raise ErrorPrecondicion(f"No encuentro '{argv[0]}' en el PATH: instálalo y vuelve a ejecutar.")
    except subprocess.TimeoutExpired:
        return -1, "", "tiempo de espera agotado"
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


class Arranque:
    def __init__(self, a, ejecutar=None, dormir=None):
        # `ejecutar` y `dormir` son inyectables: las pruebas usan una nube falsa y no esperan de verdad
        self.a, self.ejecutar, self.dormir = a, ejecutar or ejecutar_real, dormir or time.sleep
        self.aplicar = a.orden == "apply"
        self.secretos = set()  # valores que jamas se imprimen ni se registran
        self.filas, self.conflictos, self.avisos, self.hecho, self.pruebas = [], [], [], [], {}
        self.tmp = self.priv = self.s3 = self.huella = self.usr = None  # privada (texto) y llaves S3 solo en memoria
        self.priv_pendiente = self.s3_pendiente = False
        self.faltan = []  # nombres de GitHub que siguen sin existir al terminar
        self.llaves_previas = []  # huellas de las llaves de API que el usuario tecnico ya tenia
        self.respaldo = False  # la politica usa la sentencia de respaldo del paso 4
        self.gh_secretos, self.gh_variables, self.gh_ok = set(), {}, False
        self.p8 = ("AVISO", "no se pudieron comprobar los límites")

    # ------------------------------------------------------------------ utilidades
    def log(self, *partes):
        print(self.limpiar(" ".join(str(p) for p in partes)), flush=True)

    def limpiar(self, texto):
        texto = str(texto)
        for s in sorted(self.secretos, key=len, reverse=True):
            texto = texto.replace(s, "***")
        return re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[PEM redactado]", texto, flags=re.S)

    def fila(self, recurso, estado, accion):
        self.filas.append((recurso, estado, accion))

    def aviso(self, texto):
        self.avisos.append(texto)
        self.log("AVISO:", texto)

    def conflicto(self, texto):
        self.conflictos.append(texto)

    def esperar(self, condicion, error, intentos=24, pausa=PAUSA):
        """Sondea con espera inyectable hasta que la condicion se cumpla (un 404 reciente cuenta como 'aun no')."""
        for _ in range(intentos):
            try:
                if condicion():
                    return
            except ErrorOCI as e:
                if e.estado != 404:
                    raise
            self.dormir(pausa)
        raise ErrorOCI(None, None, error)

    def oci(self, args, perfil="DEFAULT", sensible=False, reintentar_404=False):
        """Unica puerta al OCI CLI: `docker run --rm` con montajes de solo lectura; devuelve el JSON o None si no hay salida.

        `sensible=True` (customer-secret-key create, api-key upload): ni la salida ni el mensaje de error se registran.
        """
        cmd = ["docker", "run", "--rm", "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "-e", "OCI_CLI_SUPPRESS_FILE_PERMISSIONS_WARNING=True", "-e", "SUPPRESS_LABEL_WARNING=True"]
        # el perfil tecnico no ve la llave del administrador, y viceversa
        montajes = [(self.tmp / "cfg", "/cfg")] + ([(self.clave_admin, "/claves/admin.pem")] if perfil == "DEFAULT"
                                                   else [(self.tmp / "claves", "/claves-tecnico")])
        for origen, destino in montajes:
            cmd += ["--mount", f"type=bind,source={origen},target={destino},readonly"]
        # --auth api_key explicito: ninguna variable de entorno puede cambiar el metodo de autenticacion
        cmd += [IMAGEN_OCI, "--config-file", "/cfg/config", "--profile", perfil, "--output", "json", "--auth", "api_key", *args]
        for intento in range(1, 7):
            rc, out, err = self.ejecutar(cmd)
            if rc == 0:
                try:
                    return json.loads(out) if out.strip() else None
                except ValueError:
                    raise ErrorOCI(None, None, "la respuesta del OCI CLI no es JSON")
            estado, codigo, msg = analizar_error(err if err.strip() else out)  # los errores de uso del CLI (codigo 2) salen por stdout
            if rc == 125 or re.search(r"Cannot connect to the Docker daemon|error during connect", err):
                raise ErrorPrecondicion(f"Docker no está disponible o no pudo iniciar el contenedor: {self.limpiar(msg)}")
            if estado is None and CONFIG_MALO.search(err):
                raise ErrorPrecondicion(f"El OCI CLI no acepta el config o la llave: {self.limpiar(msg)}")
            transitorio = (estado in TRANSITORIOS or (estado is None and (rc == -1 or RED.search(err)))
                           or (reintentar_404 and estado == 404))
            if transitorio and intento < 6:
                self.dormir(min(PAUSA * intento, 30))
                continue
            raise ErrorOCI(estado, codigo, "" if sensible else self.limpiar(msg), cmd=" ".join(args[:3]))

    def gh(self, args, entrada=None):
        return self.ejecutar(["gh", *args], entrada=entrada)  # el valor secreto viaja solo por stdin

    def rclone(self, args, entrada=None):
        """rclone en contenedor con la misma configuracion que compose.yaml; las llaves S3 viajan por entorno, no por argv."""
        acceso, secreta = self.s3
        cmd = ["docker", "run", "--rm", "--cap-drop=ALL", "--security-opt=no-new-privileges"] + (["-i"] if entrada is not None else [])
        for k, v in (("TYPE", "s3"), ("PROVIDER", "Other"), ("REGION", self.region), ("NO_CHECK_BUCKET", "true"),
                     ("ENDPOINT", endpoint_s3(self.ns, self.region))):
            cmd += ["-e", f"RCLONE_CONFIG_OCI_{k}={v}"]
        cmd += ["-e", "RCLONE_CONFIG_OCI_ACCESS_KEY_ID", "-e", "RCLONE_CONFIG_OCI_SECRET_ACCESS_KEY", IMAGEN_RCLONE, *args]
        env = {**os.environ, "RCLONE_CONFIG_OCI_ACCESS_KEY_ID": acceso, "RCLONE_CONFIG_OCI_SECRET_ACCESS_KEY": secreta}
        rc, out, _ = self.ejecutar(cmd, entrada=entrada, env=env)
        return rc, out  # el stderr de rclone no se registra

    def generar_par(self):
        """Par RSA 2048 con `oci setup keys` en contenedor. Se contesta N/A por stdin (en bytes) para que NO quede cifrada:
        la opcion --passphrase N/A cifraria con esa frase literal."""
        d = self.tmp / "claves"
        d.mkdir()
        cmd = ["docker", "run", "--rm", "-i", "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--mount", f"type=bind,source={d},target=/claves", IMAGEN_OCI,
               "setup", "keys", "--key-name", "api", "--output-dir", "/claves", "--overwrite"]
        rc, out, err = self.ejecutar(cmd, entrada="N/A\nN/A\n")
        priv, pub = d / "api.pem", d / "api_public.pem"
        if rc != 0 or not priv.is_file() or not pub.is_file():
            raise ErrorOCI(None, None, f"no pude generar el par de llaves de API (código {rc}): "
                           f"{self.limpiar(analizar_error(err if err.strip() else out)[2])}")
        texto = priv.read_text(encoding="utf-8")
        self.secretos.update({texto, texto.strip()})
        if not re.match(r"-----BEGIN (RSA )?PRIVATE KEY-----", texto):
            raise ErrorOCI(None, None, "la llave privada generada quedó cifrada o en un formato inesperado; no la subo")
        return texto, pub.read_text(encoding="utf-8")

    # ------------------------------------------------------------------ configuracion
    def leer_config(self):
        cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#",))
        try:
            leidos = cp.read(self.a.config, encoding="utf-8-sig")
        except configparser.Error as e:
            raise ErrorPrecondicion(f"No puedo interpretar el archivo de configuración ({e.__class__.__name__}).")
        if not leidos:
            raise ErrorPrecondicion(f"No pude leer el archivo de configuración: {self.a.config}")
        c = dict(cp["DEFAULT"])
        faltan = [k for k in ("user", "fingerprint", "tenancy", "region") if not c.get(k)]
        if faltan:
            raise ErrorPrecondicion(f"Faltan claves en el perfil DEFAULT del config: {', '.join(faltan)}.")
        if c.get("pass_phrase"):
            raise ErrorPrecondicion("El config trae pass_phrase: este script no maneja llaves cifradas (no escribe secretos en disco).")
        self.cfg, self.T, self.region = c, c["tenancy"], c["region"]
        ruta = Path(self.a.clave_admin).resolve()
        if not ruta.is_file():
            raise ErrorPrecondicion(f"No existe la llave privada del administrador: {ruta}")
        if "," in str(ruta):
            raise ErrorPrecondicion("La ruta de --clave-admin no puede contener comas (sintaxis de --mount de Docker).")
        with open(ruta, "rb") as f:
            cabecera = f.readline(120)
        if b"PRIVATE KEY" not in cabecera or b"ENCRYPTED" in cabecera:
            raise ErrorPrecondicion("--clave-admin debe ser una llave privada PEM sin cifrar.")
        self.clave_admin = ruta

    def escribir_config(self):
        """Config temporal con rutas del contenedor; el config pegado por el administrador trae un key_file de ejemplo."""
        c = self.cfg
        texto = f"[DEFAULT]\nuser={c['user']}\nfingerprint={c['fingerprint']}\ntenancy={self.T}\nregion={self.region}\nkey_file=/claves/admin.pem\n"
        if self.huella and self.usr:
            texto += (f"\n[TECNICO]\nuser={self.usr['id']}\nfingerprint={self.huella}\ntenancy={self.T}\n"
                      f"region={self.region}\nkey_file=/claves-tecnico/api.pem\n")
        (self.tmp / "cfg" / "config").write_text(texto, encoding="utf-8", newline="\n")

    # ------------------------------------------------------------------ paso 0: preflight
    def preflight(self):
        self.log("[0] Comprobaciones previas")
        try:
            regiones = lista(self.oci(["iam", "region-subscription", "list", "--tenancy-id", self.T]))
        except ErrorOCI as e:
            if e.estado in (401, 403, 404):
                raise ErrorPrecondicion(f"Oracle rechazó la llave del administrador (HTTP {e.estado}): revisa user, fingerprint, tenancy y el .pem; un 401 también sale si el reloj de Docker Desktop está desfasado (reinícialo).")
            raise
        casa = next((r.get("region-name") for r in regiones if r.get("is-home-region")), None)
        if casa != self.region:
            raise ErrorPrecondicion(f"La región del config ({self.region}) no es la región de origen del tenancy ({casa}). "
                                    "Always Free solo vale en la región de origen: corrige 'region' en el config. No se cambió nada.")
        self.fila("Región de origen", f"{casa} (coincide con el config)", "ninguna")
        self.ns = dato(self.oci(["os", "ns", "get"]))
        if not self.ns:
            raise ErrorPrecondicion("Oracle no devolvió el namespace de Object Storage.")
        self.fila("Namespace de Object Storage", self.ns, "ninguna")
        try:
            u = dato(self.oci(["iam", "user", "get", "--user-id", self.cfg["user"]])) or {}
            self.correo = (u.get("email") or "").strip()
            self.correo = self.correo if "@" in self.correo else None
        except ErrorOCI:
            self.correo = None
        self.limites()
        self.preflight_gh()

    def limites(self):
        """Limites de A1 por availability domain (el VM necesita 2 OCPU y 12 GB). Si no alcanzan solo se avisa: puede ser capacidad."""
        try:
            valores = [v for v in lista(self.oci(["limits", "value", "list", "-c", self.T, "--service-name", "compute", "--all"]))
                       if re.fullmatch(r"standard-a1-(core|memory)(-regional)?-count", v.get("name", ""))]
            disponible = {"core": [], "memory": []}
            for v in valores:
                cmd = ["limits", "resource-availability", "get", "--service-name", "compute", "--limit-name", v["name"], "-c", self.T]
                if v.get("scope-type") == "AD":
                    cmd += ["--availability-domain", v["availability-domain"]]
                disponible["core" if "-core-" in v["name"] else "memory"].append((dato(self.oci(cmd)) or {}).get("available") or 0)
            if not valores:
                raise ErrorOCI(None, None, "no aparecen límites standard-a1-* en 'limits value list'")
            ok = max(disponible["core"], default=0) >= 2 and max(disponible["memory"], default=0) >= 12
            detalle = f"máximo disponible por dominio: {max(disponible['core'], default=0)} núcleos y {max(disponible['memory'], default=0)} GB (se necesitan 2 y 12)"
            self.p8 = ("OK" if ok else "AVISO", detalle)
        except (ErrorOCI, KeyError, TypeError) as e:
            motivo = (e.mensaje or f"HTTP {e.estado} {e.codigo}") if isinstance(e, ErrorOCI) else repr(e)
            self.p8 = ("AVISO", f"no pude confirmar los límites de A1: {motivo}")
        self.fila("Límites de A1 (2 OCPU / 12 GB)", self.p8[1], "ninguna" if self.p8[0] == "OK" else "revisar (puede ser capacidad)")
        if self.p8[0] != "OK":
            self.aviso(f"P8: {self.p8[1]}")

    def preflight_gh(self):
        try:
            if self.gh(["auth", "status"])[0] == 0:
                rs, outs, _ = self.gh(["secret", "list", "--repo", self.a.repo_infra, "--json", "name"])
                rv, outv, _ = self.gh(["variable", "list", "--repo", self.a.repo_infra, "--json", "name,value"])
                if rs == 0 and rv == 0:
                    self.gh_secretos = {x["name"] for x in json.loads(outs or "[]")}
                    self.gh_variables = {x["name"]: x.get("value") for x in json.loads(outv or "[]")}
                    self.gh_ok = True
        except ErrorPrecondicion as e:
            self.conflicto(str(e))
        except (ValueError, KeyError, TypeError):
            self.gh_ok = False
        if self.gh_ok:
            self.fila(f"GitHub ({self.a.repo_infra})", f"sesión activa; {len(self.gh_secretos & set(SECRETOS_GH))} de {len(SECRETOS_GH)} secretos y "
                      f"{len(set(self.gh_variables) & set(VARIABLES_GH))} de {len(VARIABLES_GH)} variables ya existen", "cargar al final los que falten")
        else:
            self.fila(f"GitHub ({self.a.repo_infra})", "sin sesión de gh o sin acceso al repositorio", "CONFLICTO: gh auth login")
            self.conflicto("gh no está autenticado o no puede leer los secretos del repositorio (ejecuta 'gh auth login').")

    # ------------------------------------------------------------------ fase A: inspeccion (solo lectura)
    def buscar(self, args, nombre, que, clave="name", critico=True, items=None):
        """Busca por nombre exacto; devuelve el recurso ACTIVE. Si solo hay otros estados, registra un conflicto (o un aviso)."""
        # shortcut: comparo sin distinguir mayusculas porque Oracle podria hacerlo (sin verificar); un falso positivo solo pide revisar
        todos = [x for x in (lista(self.oci(args + ["--all"])) if items is None else items)
                 if str(x.get(clave) or "").casefold() == nombre.casefold()]
        activos = [x for x in todos if x.get("lifecycle-state") == "ACTIVE"]
        if todos and not activos:
            estados = {str(x.get("lifecycle-state")) for x in todos}
            if estados == {"DELETED"}:  # ya borrado: no estorba; si Oracle no deja reutilizar el nombre, el create lo dira
                self.aviso(f"{que} '{nombre}' aparece como DELETED; lo ignoro y lo creo de nuevo.")
            else:
                msg = (f"{que} '{nombre}' existe en estado {', '.join(sorted(estados))}; "
                       + ("todavía se está creando: espera unos segundos y vuelve a ejecutar." if "CREATING" in estados else
                          "no lo reutilizo ni creo otro con el mismo nombre. Resuélvelo con el dueño y vuelve a ejecutar."))
                self.conflicto(msg) if critico else self.aviso(msg)
        return activos[0] if activos else None

    def inspeccionar(self):
        self.log("[1-8] Inspeccionando el estado actual (solo lectura)")
        T = self.T
        self.comp = self.buscar(["iam", "compartment", "list", "-c", T], N_COMP, "El compartimento")
        self.fila(f"Compartimento {N_COMP}", "activo" if self.comp else "no existe", "ninguna" if self.comp else "crear bajo el tenancy")
        self.grupo = self.buscar(["iam", "group", "list", "-c", T], N_GRUPO, "El grupo")
        self.fila(f"Grupo {N_GRUPO}", "activo" if self.grupo else "no existe", "ninguna" if self.grupo else "crear")
        self.usr = self.buscar(["iam", "user", "list", "-c", T], N_USUARIO, "El usuario")
        self.fila(f"Usuario {N_USUARIO}", "activo" if self.usr else "no existe", "ninguna" if self.usr else "crear (sin contraseña de consola)")
        self.caps_mal, self.en_grupo = ["nuevo"], False
        if self.usr:
            u = dato(self.oci(["iam", "user", "get", "--user-id", self.usr["id"]])) or {}
            self.caps_mal = desviaciones(u.get("capabilities"))
        if self.grupo:  # N13 anticipado: el grupo solo puede tener al usuario tecnico
            miembros = lista(self.oci(["iam", "group", "list-users", "--group-id", self.grupo["id"], "-c", T, "--all"]))
            self.en_grupo = bool(self.usr) and any(m["id"] == self.usr["id"] for m in miembros)
            ajenos = [m.get("name") for m in miembros if not self.usr or m["id"] != self.usr["id"]]
            if ajenos:
                self.conflicto(f"El grupo '{N_GRUPO}' ya tiene otros miembros ({ajenos}); debe tener solo a {N_USUARIO}.")
        self.fila("Capacidades del usuario", "solo API keys y llaves S3" if not self.caps_mal else (
            "usuario nuevo" if self.caps_mal == ["nuevo"] else f"desviaciones: {', '.join(self.caps_mal)}"),
            "ninguna" if not self.caps_mal else "dejar SOLO can-use-api-keys y can-use-customer-secret-keys")
        self.fila("Membresía en el grupo", "es miembro" if self.en_grupo else "no es miembro", "ninguna" if self.en_grupo else "agregar al grupo")
        self.inspeccionar_politica()
        self.inspeccionar_llaves()
        self.buckets = {}
        for nombre, versionado in ((B_ESTADO, True), (B_ARCHIVOS, False)):
            self.inspeccionar_bucket(nombre, versionado)
        self.inspeccionar_presupuesto()
        self.fila("Verificación (P1-P5, P7-P8, N1, N2, N4, N6, N7, N11-N13)", "pendiente", "ejecutar al aplicar; si algo falla no se carga nada en GitHub")

    def inspeccionar_politica(self):
        todas = lista(self.oci(["iam", "policy", "list", "-c", self.T, "--all"]))
        self.pol = self.buscar(None, N_POLITICA, "La política", items=todas)
        otras = [p.get("name") for p in todas if p.get("name") != N_POLITICA and any(nombra_grupo(s) for s in p.get("statements") or [])]
        if otras:  # N12 anticipado: otra politica daria permisos de mas al usuario tecnico
            self.conflicto(f"Otras políticas nombran al grupo '{N_GRUPO}' ({otras}): el usuario técnico tendría permisos de más. Revísalas y vuelve a ejecutar.")
        estado, accion = "no existe", f"crear en el tenancy con {len(SENTENCIAS)} sentencias"
        if self.pol:
            actual = {" ".join(s.split()) for s in self.pol.get("statements") or []}
            if actual == set(SENTENCIAS):
                estado, accion = "con las sentencias esperadas", "ninguna"
            elif actual == set(SENTENCIAS_RESPALDO):
                self.respaldo, estado, accion = True, "con la variante de respaldo (inspect compartments in tenancy)", "ninguna"
            else:
                estado, accion = "existe con OTRAS sentencias", "CONFLICTO: no se toca"
                self.conflicto(f"La política '{N_POLITICA}' ya existe con otras sentencias; no la modifico. "
                               f"Faltan: {sorted(set(SENTENCIAS) - actual) or 'ninguna'}. Sobran: {sorted(actual - set(SENTENCIAS) - set(SENTENCIAS_RESPALDO)) or 'ninguna'}.")
        self.fila(f"Política {N_POLITICA}", estado, accion)

    def inspeccionar_llaves(self):
        uid = self.usr["id"] if self.usr else None
        sobre = self.a.sobrescribir_secretos
        llaves = lista(self.oci(["iam", "user", "api-key", "list", "--user-id", uid, "--all"])) if uid else []
        self.llaves_previas = [str(k.get("fingerprint")) for k in llaves]
        self.gen_llave = True
        if "OCI_PRIVATE_KEY" in self.gh_secretos and not sobre:
            self.gen_llave, estado, accion = False, f"{len(llaves)} de 3; el secreto OCI_PRIVATE_KEY ya existe", "no se genera otra (la privada no se puede releer)"
        elif len(llaves) >= 3:
            self.gen_llave, estado, accion = False, "3 de 3 (máximo de OCI)", "no se genera otra: borra una en la consola"
            self.aviso("El usuario técnico ya tiene 3 llaves de API y OCI_PRIVATE_KEY no está en GitHub: no puedo generar otra.")
        else:
            estado, accion = f"{len(llaves)} de 3", "generar par RSA 2048 y subir la pública"
            if "OCI_FINGERPRINT" in self.gh_secretos and not sobre:  # un par nuevo no puede convivir con la huella vieja
                self.conflicto("OCI_FINGERPRINT ya existe en GitHub sin OCI_PRIVATE_KEY: el par quedaría incoherente. Usa --sobrescribir-secretos.")
        self.fila("Llave de API del usuario técnico", estado, accion)
        llaves_s3 = lista(self.oci(["iam", "customer-secret-key", "list", "--user-id", uid, "--all"])) if uid else []
        existe = any(k.get("display-name") == N_LLAVE_S3 for k in llaves_s3)
        en_gh = {"OCI_S3_ACCESS_KEY", "OCI_S3_SECRET_KEY"} <= self.gh_secretos
        self.crear_s3 = not existe and len(llaves_s3) < 2 and (not en_gh or sobre)
        if self.crear_s3 and {"OCI_S3_ACCESS_KEY", "OCI_S3_SECRET_KEY"} & self.gh_secretos and not sobre:
            self.conflicto("Solo uno de los secretos OCI_S3_* existe en GitHub: el par quedaría incoherente. Usa --sobrescribir-secretos.")
        if existe:
            estado, accion = "ya existe (el secreto no se puede releer)", "ninguna"
            if not en_gh:
                self.aviso(f"La Customer Secret Key '{N_LLAVE_S3}' existe pero sus llaves no están en GitHub y no se pueden recuperar: "
                           "bórrala en la consola (Mi perfil > Llaves secretas del cliente) y vuelve a ejecutar apply.")
        elif not self.crear_s3:
            estado, accion = ("las llaves S3 ya están en GitHub" if en_gh else "el usuario ya tiene 2 llaves (máximo)"), "no se crea otra"
        else:
            estado, accion = "no existe", "crear (el secreto se muestra una sola vez; queda en memoria hasta GitHub)"
        self.fila(f"Customer Secret Key {N_LLAVE_S3}", estado, accion)

    def inspeccionar_bucket(self, nombre, versionado):
        try:
            b = dato(self.oci(["os", "bucket", "get", "--namespace-name", self.ns, "--bucket-name", nombre]))
        except ErrorOCI as e:
            if e.estado != 404:
                raise
            b = None
        self.buckets[nombre] = b
        estado, accion = "no existe", "crear (privado, Standard" + (", versionado)" if versionado else ")")
        if b:
            estado, accion = "existe", "ninguna"
            if not self.comp or b.get("compartment-id") != self.comp["id"]:
                self.conflicto(f"El bucket '{nombre}' existe fuera del compartimento {N_COMP}; no lo toco.")
                accion = "CONFLICTO"
            elif b.get("public-access-type") != "NoPublicAccess":
                self.conflicto(f"El bucket '{nombre}' no es privado ({b.get('public-access-type')}); no lo toco.")
                accion = "CONFLICTO"
            elif versionado and b.get("versioning") != "Enabled":
                estado, accion = f"existe sin versionado ({b.get('versioning')})", "activar versionado"
        self.fila(f"Bucket {nombre}", estado, accion)

    def inspeccionar_presupuesto(self):
        self.pres, self.pres_ajeno, self.reglas_faltan, self.pres_ok = None, None, list(REGLAS), bool(self.correo)
        if not self.correo:
            self.fila(f"Presupuesto {N_PRESUPUESTO}", "—", "OMITIDO: el administrador no tiene correo en OCI (no uso otro)")
            self.aviso("El administrador no tiene correo en OCI: se omite el presupuesto de USD 1.")
            return
        try:
            todos = lista(self.oci(["budgets", "budget", "budget", "list", "-c", self.T, "--target-type", "ALL", "--all"]))
            self.pres = self.buscar([], N_PRESUPUESTO, "El presupuesto", clave="display-name", critico=False, items=todos)
            if self.pres:
                reglas = lista(self.oci(["budgets", "budget", "alert-rule", "list", "--budget-id", self.pres["id"], "--all"]))
                self.reglas_faltan = [r for r in REGLAS if not any(
                    x.get("type") == r[0] and float(x.get("threshold") or -1) == r[1] and x.get("threshold-type") == "PERCENTAGE" for x in reglas)]
            else:
                # Oracle limita los presupuestos del tenancy (400 LimitExceeded al crear otro, observado el 2026-11-09): si ya hay uno activo lo respeto
                ajenos = [x for x in todos if x.get("lifecycle-state") == "ACTIVE"]
                if ajenos:
                    a = self.pres_ajeno = ajenos[0]
                    self.pres_ok = False
                    self.fila(f"Presupuesto {N_PRESUPUESTO}",
                              f"ya existe '{a.get('display-name')}' (USD {a.get('amount')}/{a.get('reset-period')}, {a.get('alert-rule-count')} alertas)",
                              "ninguna: no creo otro ni toco el existente")
                    return
            self.fila(f"Presupuesto {N_PRESUPUESTO}", "existe" if self.pres else "no existe",
                      "ninguna" if self.pres and not self.reglas_faltan else f"crear (USD 1/mes) y {len(self.reglas_faltan)} alertas")
        except ErrorOCI as e:
            self.pres_ok = False
            self.fila(f"Presupuesto {N_PRESUPUESTO}", "no disponible", "OMITIDO (es opcional)")
            self.aviso(f"No pude consultar presupuestos ({e.estado} {e.codigo}); continúo sin ellos.")

    def mostrar_tabla(self, titulo):
        cab = ("Recurso", "Estado actual", "Acción")
        w = [max(len(f[i]) for f in self.filas + [cab]) for i in range(3)]
        self.log(f"\n{titulo}")
        for f in [cab, tuple("-" * n for n in w)] + self.filas:
            self.log("  ".join(c.ljust(n) for c, n in zip(f, w)).rstrip())

    # ------------------------------------------------------------------ fase B: cambios (solo apply)
    def comprobar(self, condicion, que):
        self.esperar(condicion, f"{que} no aparece como se esperaba después de crearlo")

    def hacer(self):
        T = self.T
        self.log("\n[1] Compartimento")
        if not self.comp:
            c = dato(self.oci(["iam", "compartment", "create", "-c", T, "--name", N_COMP, "--freeform-tags", TAGS,
                               "--description", "Entorno de pruebas de Trayecta Go (solo Always Free)"]))
            self.esperar(lambda: dato(self.oci(["iam", "compartment", "get", "-c", c["id"]])).get("lifecycle-state") == "ACTIVE",
                         "el compartimento no llegó a ACTIVE")
            self.comp = c
            self.hecho.append(f"compartimento {N_COMP} creado")
        self.log("[2] Grupo")
        if not self.grupo:
            self.grupo = dato(self.oci(["iam", "group", "create", "-c", T, "--name", N_GRUPO, "--freeform-tags", TAGS,
                                        "--description", "Automatizacion de Trayecta Go (entorno pruebas)"]))
            self.comprobar(lambda: self.buscar(["iam", "group", "list", "-c", T], N_GRUPO, "El grupo"), "el grupo")
            self.hecho.append(f"grupo {N_GRUPO} creado")
        self.log("[3] Usuario técnico")
        self.crear_usuario()
        self.log("[4] Política")
        if not self.pol:
            self.pol = dato(self.oci(["iam", "policy", "create", "-c", T, "--name", N_POLITICA, "--freeform-tags", TAGS,
                                      "--description", "Permisos minimos de la automatizacion de Trayecta Go en el compartimento de pruebas",
                                      "--statements", json.dumps(SENTENCIAS)], reintentar_404=True))
            self.comprobar(lambda: self.estado_politica() == set(SENTENCIAS), "la política")
            self.hecho.append(f"política {N_POLITICA} creada con {len(SENTENCIAS)} sentencias")
        self.log("[5] Llave de API del usuario técnico")
        self.crear_llave_api()
        self.log("[7] Buckets")
        self.crear_buckets()
        self.log("[8] Presupuesto (opcional)")
        self.crear_presupuesto()

    def crear_llave_s3(self):
        self.log("[6] Customer Secret Key (al final: solo si las demás pruebas pasaron)")
        r = dato(self.oci(["iam", "customer-secret-key", "create", "--user-id", self.usr["id"], "--display-name", N_LLAVE_S3],
                          sensible=True, reintentar_404=True)) or {}
        self.s3_pendiente = True  # desde aqui el secreto solo existe en memoria
        self.s3 = (r["id"], r["key"])  # access key y secret key: hasta cargarlas en GitHub
        self.secretos.update(self.s3)
        self.comprobar(lambda: any(k.get("display-name") == N_LLAVE_S3 for k in lista(self.oci(
            ["iam", "customer-secret-key", "list", "--user-id", self.usr["id"], "--all"]))), "la llave S3")
        self.hecho.append(f"Customer Secret Key {N_LLAVE_S3} creada")

    def estado_politica(self):
        p = self.buscar(["iam", "policy", "list", "-c", self.T], N_POLITICA, "La política")
        return {" ".join(s.split()) for s in p.get("statements") or []} if p else None

    def crear_usuario(self):
        if not self.usr:
            base = ["iam", "user", "create", "-c", self.T, "--name", N_USUARIO, "--freeform-tags", TAGS,
                    "--description", "Usuario tecnico de Trayecta Go: OpenTofu y respaldos (solo llaves de API y S3)"]
            try:
                r = self.oci(base)
            except ErrorOCI as e:  # los dominios de identidad exigen correo primario; un 400 no crea nada, así que reintentar es seguro
                if e.estado != 400 or not (e.codigo == "IdcsConversionError" or CORREO_EXIGIDO.search(e.mensaje or "")):
                    raise
                if not self.correo:
                    raise ErrorPrecondicion("Oracle exige correo para crear el usuario y el administrador no tiene uno en OCI. "
                                            "No uso otro correo: agrégalo al administrador y vuelve a ejecutar.")
                r = self.oci(base + ["--email", correo_derivado(self.correo)])
            self.usr = dato(r)
            self.esperar(lambda: (dato(self.oci(["iam", "user", "get", "--user-id", self.usr["id"]])) or {}).get("lifecycle-state") == "ACTIVE",
                         "el usuario no llegó a ACTIVE")
            self.hecho.append(f"usuario {N_USUARIO} creado")
        uid = self.usr["id"]
        if self.caps_mal:
            self.oci(["iam", "user", "update-user-capabilities", "--user-id", uid, "--can-use-console-password", "false",
                      "--can-use-auth-tokens", "false", "--can-use-smtp-credentials", "false", "--can-use-db-credentials", "false",
                      "--can-use-o-auth2-client-credentials", "false", "--can-use-api-keys", "true",
                      "--can-use-customer-secret-keys", "true"], reintentar_404=True)
            self.esperar(lambda: not desviaciones((dato(self.oci(["iam", "user", "get", "--user-id", uid])) or {}).get("capabilities")),
                         "las capacidades del usuario no quedaron como se esperaba (revisa los can-use-* en la consola)")
            self.hecho.append("capacidades del usuario fijadas (solo API keys y llaves S3)")
        if not self.en_grupo:
            self.oci(["iam", "group", "add-user", "--user-id", uid, "--group-id", self.grupo["id"]], reintentar_404=True)
            self.comprobar(lambda: any(g["id"] == self.grupo["id"] for g in lista(self.oci(
                ["iam", "user", "list-groups", "--user-id", uid, "-c", self.T, "--all"]))), "la membresía")
            self.hecho.append("usuario agregado al grupo")

    def crear_llave_api(self):
        if not self.gen_llave:
            return
        priv, pub = self.generar_par()
        self.priv, self.priv_pendiente = priv, True  # la privada vive en el directorio temporal hasta cargarla en GitHub
        esperada = huella_md5(pub)
        r = dato(self.oci(["iam", "user", "api-key", "upload", "--user-id", self.usr["id"], "--key", pub],
                          sensible=True, reintentar_404=True)) or {}
        if r.get("fingerprint") != esperada:
            raise ErrorOCI(None, None, "la huella que devuelve Oracle no coincide con la calculada localmente")
        self.comprobar(lambda: any(k.get("fingerprint") == esperada for k in lista(self.oci(
            ["iam", "user", "api-key", "list", "--user-id", self.usr["id"], "--all"]))), "la llave de API")
        self.huella = esperada
        self.escribir_config()  # agrega el perfil TECNICO
        self.hecho.append(f"llave de API subida (huella {esperada})")
        if self.llaves_previas:
            self.aviso(f"El usuario técnico ya tenía {len(self.llaves_previas)} llave(s) de API (huellas {', '.join(self.llaves_previas)}) y siguen vigentes: "
                       "borra las que no uses para no dejar credenciales sueltas.")

    def crear_buckets(self):
        for nombre, versionado in ((B_ESTADO, True), (B_ARCHIVOS, False)):
            b = self.buckets[nombre]
            if b is None:
                self.oci(["os", "bucket", "create", "--namespace-name", self.ns, "--name", nombre, "-c", self.comp["id"],
                          "--storage-tier", "Standard", "--public-access-type", "NoPublicAccess", "--freeform-tags", TAGS]
                         + (["--versioning", "Enabled"] if versionado else []))
                self.hecho.append(f"bucket {nombre} creado")
            elif versionado and b.get("versioning") != "Enabled":
                self.oci(["os", "bucket", "update", "--namespace-name", self.ns, "--bucket-name", nombre, "--versioning", "Enabled"])
                self.hecho.append(f"versionado activado en {nombre}")
            else:
                continue
            nuevo = dato(self.oci(["os", "bucket", "get", "--namespace-name", self.ns, "--bucket-name", nombre])) or {}
            if (nuevo.get("public-access-type"), nuevo.get("storage-tier")) != ("NoPublicAccess", "Standard") or (
                    versionado and nuevo.get("versioning") != "Enabled"):
                raise ErrorOCI(None, None, f"el bucket {nombre} no quedó privado, Standard y con el versionado esperado")

    def crear_presupuesto(self):
        if not self.pres_ok:
            return
        try:
            if not self.pres:
                self.pres = dato(self.oci(["budgets", "budget", "budget", "create", "-c", self.T, "--amount", "1", "--reset-period", "MONTHLY",
                                           "--target-type", "COMPARTMENT", "--targets", json.dumps([self.T]), "--display-name", N_PRESUPUESTO,
                                           "--description", "Alerta de cobro inesperado (Always Free)", "--freeform-tags", TAGS]))
                self.hecho.append(f"presupuesto {N_PRESUPUESTO} creado (USD 1 mensual sobre el tenancy)")
            for tipo, umbral, nombre in self.reglas_faltan:
                self.oci(["budgets", "budget", "alert-rule", "create", "--budget-id", self.pres["id"], "--type", tipo, "--threshold", str(umbral),
                          "--threshold-type", "PERCENTAGE", "--display-name", nombre, "--recipients", self.correo, "--freeform-tags", TAGS,
                          "--message", "Trayecta Go: hay gasto o pronostico de gasto en la cuenta de Oracle. Revisa la consola."])
                self.hecho.append(f"alerta {nombre} creada")
        except ErrorOCI as e:
            self.aviso(f"Presupuesto: {e.estado} {e.codigo}. Continúo sin él (es opcional).")

    # ------------------------------------------------------------------ paso 9: verificacion
    def prueba(self, id_, args, ok=True, propagacion=0, validar=None):
        """Prueba del perfil TECNICO. ok=True debe responder; ok=False debe recibir 404 NotAuthorizedOrNotFound (o 403).
        Oracle propaga la llave de API y la politica por nodos: en las positivas se reintenta con espera mientras conteste 401 o 404, y en las
        negativas solo ante un 401 (un nodo que aun no conoce la llave; medido el 2026-11-09). Un 404 o un 403 negativo es la respuesta buscada."""
        if id_ in self.a.omitir_prueba:  # expectativa sin verificar contra Oracle: el dueño decide omitirla y queda registrada
            self.pruebas[id_] = ("OMITIDA", "omitida a pedido con --omitir-prueba")
            return self.pruebas[id_] + (None,)
        http = None
        reintentos, reintenta = (propagacion, (401, 404)) if ok else (REINTENTOS_401, (401,))
        for intento in range(reintentos + 1):
            try:
                r = self.oci(args, perfil="TECNICO")
                error = ("el usuario técnico pudo ejecutarlo (permisos de más)" if not ok else validar(r) if validar else None)
                res = ("FALLA", error) if error else ("OK", "respondió")
            except ErrorOCI as e:
                http = e.estado
                if e.estado in reintenta and intento < reintentos:
                    self.dormir(PAUSA)
                    continue
                if not ok and (e.estado, e.codigo) == (404, "NotAuthorizedOrNotFound"):
                    res = ("OK", "404 NotAuthorizedOrNotFound")
                elif not ok and e.estado == 403:  # tambien es una denegacion: el usuario tecnico no pudo hacerlo
                    res = ("OK", f"403 {e.codigo} (denegado)")
                else:
                    res = ("FALLA", f"HTTP {e.estado} {e.codigo}" + ("" if ok else " (se esperaba 404 NotAuthorizedOrNotFound)"))
            break
        self.pruebas[id_] = res
        return res + (http,)

    def verificar(self):
        self.log("\n[9] Verificación (puede tardar unos minutos por la propagación de Oracle)")
        T, C, ns = self.T, self.comp["id"], self.ns
        if self.priv:
            hay = lambda r: None if lista(r) else "la respuesta vino vacía"
            self.prueba("P2", ["compute", "image", "list", "-c", C, "--operating-system", "Canonical Ubuntu", "--operating-system-version", "24.04",
                               "--shape", "VM.Standard.A1.Flex", "--limit", "1"], propagacion=PROPAGACION, validar=hay)
            for id_, cmd in (("P3-vcn", ["network", "vcn", "list"]), ("P3-instancias", ["compute", "instance", "list"]),
                             ("P3-volumenes", ["bv", "volume", "list"])):
                self.prueba(id_, cmd + ["-c", C], propagacion=6)
            ads = ["iam", "availability-domain", "list", "-c", T]
            res = self.prueba("P1", ads, propagacion=6, validar=hay)
            if res[0] != "OK" and res[2] == 404 and self.pruebas["P2"][0] == "OK" and not self.respaldo:
                # P2 pasa, asi que la politica ya rige: la sentencia con 'where request.operation' no alcanza para ListAvailabilityDomains
                self.log("P1 falla con 404 aunque la política ya rige: reemplazo la última sentencia por la variante de respaldo.")
                self.oci(["iam", "policy", "update", "--policy-id", self.pol["id"], "--statements", json.dumps(SENTENCIAS_RESPALDO), "--version-date", "", "--force"])
                self.respaldo = True
                self.hecho.append(f"política actualizada: sentencia de respaldo '{SENTENCIAS_RESPALDO[-1]}'")
                self.prueba("P1", ads, propagacion=PROPAGACION, validar=hay)
            for b in (B_ESTADO, B_ARCHIVOS):
                self.prueba(f"P4-{b}", ["os", "object", "list", "--namespace-name", ns, "--bucket-name", b], propagacion=6)
            # N1 lee el tenancy (GetCompartment): `iam compartment list` con accessLevel=ANY no comprueba permisos y responde a cualquiera (observado el 2026-11-09)
            for id_, cmd in (("N1", ["iam", "compartment", "get", "--compartment-id", T]), ("N2", ["network", "vcn", "list", "-c", T]),
                             ("N4", ["iam", "user", "list", "-c", T]), ("N6", ["iam", "policy", "list", "-c", T]),
                             ("N7", ["budgets", "budget", "budget", "list", "-c", T, "--target-type", "ALL"])):
                if id_ == "N1" and self.respaldo:
                    self.pruebas[id_] = ("NO APLICA", "la política usa la sentencia de respaldo (inspect compartments in tenancy)")
                else:
                    self.prueba(id_, cmd, ok=False)
        else:
            for id_ in ("P1", "P2", "P3", "P4", "N1", "N2", "N4", "N6", "N7"):
                self.pruebas[id_] = ("OMITIDA", "no hay llave privada del usuario técnico en esta ejecución (ya existía o no se pudo generar)")
        self.pruebas_admin()
        if self.crear_s3 and not any(e == "FALLA" for e, _ in self.pruebas.values()):
            self.crear_llave_s3()
        if self.s3:
            self.prueba_s3()
        else:
            self.pruebas["P5"] = ("OMITIDA", "las llaves S3 no se crearon en esta ejecución (el secreto no se puede releer, o fallaron otras pruebas)")

    def s3_cmd(self, args, entrada=None, intentos=1):
        """rclone con reintentos: aun con la llave ya aceptada, algunas peticiones siguen dando SignatureDoesNotMatch un buen rato (Oracle la
        propaga por nodos). Un 3 o un 4 de rclone ("no existe") y un 125 o mas (Docker no pudo ejecutarlo) no se arreglan esperando."""
        for i in range(intentos):
            rc, out = self.rclone(args, entrada)
            if rc in (0, 3, 4) or rc >= 125 or i == intentos - 1:
                return rc, out
            self.dormir(PAUSA_S3)

    def esperar_llave_s3(self):
        """Espera a que la llave S3 rija de forma estable (ESTABLE_S3 listados seguidos) y devuelve 0, o el código de rclone si no llegó."""
        seguidos, rc = 0, 1
        for intento in range(1, ESPERA_S3 + 1):
            rc, _ = self.rclone(["lsf", f"oci:{B_ESTADO}"])
            if rc >= 125 or rc == 3:  # Docker no corre rclone, o la API S3 no ve el bucket: esperar no lo arregla
                return rc
            seguidos = seguidos + 1 if rc == 0 else 0
            if seguidos >= ESTABLE_S3:
                return 0
            if intento % 6 == 0:
                self.log(f"  P5: la llave S3 aún no rige de forma estable ({intento} intentos de {ESPERA_S3}); Oracle la propaga por nodos, sigo esperando…")
            self.dormir(PAUSA_S3)
        return rc or 1

    def prueba_s3(self):
        """P5: la API S3 con la llave nueva. Unica operacion de borrado del script: el objeto de humo que ella misma crea."""
        ruta = f"oci:{B_ARCHIVOS}/humo/prueba.txt"
        fallo, subido = None, False
        try:
            rc = self.esperar_llave_s3()
            if rc == 3:
                fallo = ("rclone no encuentra el bucket de estado (código 3): la API S3 puede ver solo los buckets del compartimento designado para S3; "
                         "revisa `oci os ns get-metadata` (default-s3-compartment-id)")
            elif rc >= 125:
                fallo = f"rclone no pudo ejecutarse en Docker (código {rc})"
            elif rc:
                fallo = f"la llave S3 no rigió de forma estable en {ESPERA_S3} intentos de {PAUSA_S3} s (rclone terminó con código {rc})"
            if not fallo:
                for nombre, args, entrada in (("listar el bucket de archivos", ["lsf", f"oci:{B_ARCHIVOS}"], None),
                                              ("crear el objeto", ["rcat", ruta], "humo1"),
                                              ("sobrescribir el objeto", ["rcat", ruta], "humo2")):
                    rc, _ = self.s3_cmd(args, entrada, REINTENTOS_S3)
                    if rc:
                        fallo = f"{nombre} (rclone terminó con código {rc})"
                        break
                    subido = subido or nombre == "crear el objeto"
            if not fallo:
                rc, out = self.s3_cmd(["cat", ruta], intentos=REINTENTOS_S3)
                if rc or out != "humo2":
                    fallo = "leer el objeto: el contenido no es el de la sobrescritura"
        finally:
            if subido:
                self.s3_cmd(["deletefile", ruta], intentos=REINTENTOS_S3)
                rc2, listado = self.s3_cmd(["lsf", f"oci:{B_ARCHIVOS}/humo/"], intentos=REINTENTOS_S3)
                # en S3 el prefijo desaparece con su ultimo objeto: rclone responde 3 ("directorio no encontrado"), que aqui significa borrado
                if rc2 not in (0, 3) or "prueba.txt" in listado:
                    fallo = fallo or f"borrar el objeto de humo; bórralo a mano: {B_ARCHIVOS}/humo/prueba.txt"
        self.pruebas["P5"] = ("FALLA", fallo) if fallo else ("OK", "listar, crear, sobrescribir, leer y borrar el objeto de humo")

    def pruebas_admin(self):
        uid, T = self.usr["id"], self.T
        mal = desviaciones((dato(self.oci(["iam", "user", "get", "--user-id", uid])) or {}).get("capabilities"))
        self.pruebas["N11"] = ("FALLA", f"capacidades distintas de las esperadas: {mal}") if mal else ("OK", "solo API keys y llaves S3")
        politicas = lista(self.oci(["iam", "policy", "list", "-c", T, "--all"]))
        propia = next((p for p in politicas if p.get("name") == N_POLITICA), None)
        esperadas = set(SENTENCIAS_RESPALDO if self.respaldo else SENTENCIAS)
        actuales = {" ".join(s.split()) for s in (propia or {}).get("statements") or []}
        otras = [p["name"] for p in politicas if p.get("name") != N_POLITICA and any(nombra_grupo(s) for s in p.get("statements") or [])]
        if actuales != esperadas or otras:
            self.pruebas["N12"] = ("FALLA", f"sentencias distintas de las esperadas o políticas ajenas que nombran al grupo: {otras or sorted(actuales ^ esperadas)}")
        else:
            self.pruebas["N12"] = ("OK", f"exactamente las {len(esperadas)} sentencias esperadas")
        miembros = {u["id"] for u in lista(self.oci(["iam", "group", "list-users", "--group-id", self.grupo["id"], "-c", T, "--all"]))}
        self.pruebas["N13"] = ("OK", "solo el usuario técnico") if miembros == {uid} else ("FALLA", f"el grupo tiene {len(miembros)} miembros")
        self.pruebas["P7"] = ("OK", f"la región de origen coincide con la del config ({self.region})")
        self.pruebas["P8"] = self.p8  # solo aviso: puede ser capacidad, no permisos

    # ------------------------------------------------------------------ paso 10: GitHub
    def cargar_github(self):
        self.log("\n[10] Cargando secretos y variables en GitHub")
        repo, sobre = self.a.repo_infra, self.a.sobrescribir_secretos
        presentes = set(self.gh_secretos)  # secretos que existen en GitHub al terminar de cargar
        valores = {"OCI_TENANCY_OCID": self.T, "OCI_USER_OCID": self.usr["id"], "OCI_FINGERPRINT": self.huella, "OCI_PRIVATE_KEY": self.priv,
                   "OCI_COMPARTMENT_OCID": self.comp["id"], "OCI_S3_ACCESS_KEY": self.s3 and self.s3[0], "OCI_S3_SECRET_KEY": self.s3 and self.s3[1]}
        for nombre in SECRETOS_GH:
            if nombre in self.gh_secretos and not (valores[nombre] and sobre):
                self.log(f"  {nombre}: ya existe, no se modifica (usa --sobrescribir-secretos para reemplazarlo)")
            elif not valores[nombre]:
                self.log(f"  {nombre}: sin valor nuevo en esta ejecución")
            else:
                rc, _, err = self.gh(["secret", "set", nombre, "--repo", repo], entrada=valores[nombre])  # valor por stdin, nunca por argv
                if rc:
                    raise RuntimeError(f"gh no pudo guardar el secreto {nombre} (código {rc}): {self.limpiar(err.strip()[:200])}")
                self.log(f"  {nombre}: cargado")
                presentes.add(nombre)
        self.priv_pendiente = self.s3_pendiente = False
        incompleto = [n for n in SECRETOS_GH if n not in presentes]
        for nombre, valor in (("OCI_NAMESPACE", self.ns), ("OCI_REGION", self.region)):
            if nombre == "OCI_REGION" and incompleto:  # activa plan-pruebas: solo con los secretos completos
                self.aviso(f"No cargo OCI_REGION porque faltan secretos ({', '.join(incompleto)}): activaría plan-pruebas con credenciales incompletas.")
                continue
            if self.gh_variables.get(nombre) == valor:
                self.log(f"  {nombre}: ya tiene ese valor")
            elif nombre in self.gh_variables and not sobre:
                self.aviso(f"La variable {nombre} ya existe con otro valor y no se sobrescribe (usa --sobrescribir-secretos).")
            else:
                rc, _, err = self.gh(["variable", "set", nombre, "--repo", repo, "--body", valor])
                if rc:
                    raise RuntimeError(f"gh no pudo guardar la variable {nombre} (código {rc}): {self.limpiar(err.strip()[:200])}")
                self.log(f"  {nombre}: cargada")
        rs, outs, _ = self.gh(["secret", "list", "--repo", repo, "--json", "name"])
        rv, outv, _ = self.gh(["variable", "list", "--repo", repo, "--json", "name"])
        presentes = {x["name"] for x in json.loads(outs or "[]")} | {x["name"] for x in json.loads(outv or "[]")}
        self.faltan = [n for n in SECRETOS_GH + VARIABLES_GH if n not in presentes] if rs == 0 and rv == 0 else ["(no pude releer GitHub)"]

    # ------------------------------------------------------------------ paso 11: resultado
    def escribir_resultado(self):
        salida = Path(self.a.salida)
        nueva = not salida.exists() or not any(salida.iterdir())
        salida.mkdir(parents=True, exist_ok=True)
        if nueva:  # solo en una carpeta propia: no piso el .gitignore de un repositorio ajeno
            (salida / ".gitignore").write_text("*\n", encoding="utf-8")  # que git no registre nunca esta carpeta
        ref = lambda x: {"nombre": x.get("name"), "ocid": x.get("id")}
        resultado = {
            "generado": datetime.now(timezone.utc).isoformat(timespec="seconds"), "region": self.region, "namespace": self.ns,
            "tenancy_ocid": self.T, "compartimento": ref(self.comp), "grupo": ref(self.grupo), "usuario": ref(self.usr),
            "politica": {**ref(self.pol), "sentencias": SENTENCIAS_RESPALDO if self.respaldo else SENTENCIAS,
                         "variante": "respaldo" if self.respaldo else "principal"},
            "huella_llave_api": self.huella, "llave_s3": {"nombre": N_LLAVE_S3, "creada_en_esta_ejecucion": bool(self.s3)},
            "buckets": [B_ESTADO, B_ARCHIVOS],
            "presupuesto": ({"nombre": p.get("display-name"), "ocid": p.get("id"), "propio": p is self.pres}
                            if (p := self.pres or self.pres_ajeno) else None),
            "github": {"repo": self.a.repo_infra, "faltan": self.faltan},
            "pruebas": {k: {"estado": v[0], "detalle": v[1]} for k, v in self.pruebas.items()},
            "cambios": self.hecho, "avisos": self.avisos}
        (salida / "resultado.json").write_text(self.limpiar(json.dumps(resultado, indent=2, ensure_ascii=False)), encoding="utf-8")
        self.log(f"\nResultado (solo identificadores, sin secretos): {salida / 'resultado.json'}")

    def resumen(self):
        self.log("\nPruebas:")
        ancho = max(len(k) for k in self.pruebas)
        for k, (estado, detalle) in self.pruebas.items():
            self.log(f"  {k.ljust(ancho)}  {estado:<9}  {detalle}")
        for h in self.hecho:
            self.log(f"  hecho: {h}")
        if not self.hecho:
            self.log("  No hubo cambios en Oracle: todo estaba como se esperaba.")

    def parcial(self):
        """Lo que ya se creo en Oracle cuando una corrida termina a medias (para retomar sin adivinar)."""
        if self.hecho:
            print("Hecho hasta aquí: " + "; ".join(self.hecho), file=sys.stderr)

    # ------------------------------------------------------------------ orquestacion
    def correr(self):
        try:
            self.leer_config()
            self.tmp = Path(tempfile.mkdtemp(prefix="bootstrap-oci-"))
            (self.tmp / "cfg").mkdir()
            self.escribir_config()
            self.preflight()
            self.inspeccionar()
            self.mostrar_tabla("Plan" if not self.aplicar else "Plan (lo que se hará)")
            for c in self.conflictos:
                self.log("CONFLICTO:", c)
            if not self.aplicar:
                self.log("\nModo plan: no se creó ni se modificó nada." + (f" Conflictos: {len(self.conflictos)}." if self.conflictos else ""))
                return 0
            if self.conflictos:
                raise ErrorPrecondicion("Hay conflictos; no se creó ni se modificó nada. Resuélvelos y vuelve a ejecutar.")
            self.hacer()
            self.verificar()
            fallas = [k for k, (e, _) in self.pruebas.items() if e == "FALLA"]
            self.resumen()
            if fallas:
                self.log(f"\nFALLARON LAS PRUEBAS {fallas}: no se cargó nada en GitHub.")
                return 1
            self.cargar_github()
            self.escribir_resultado()
            if self.faltan:
                self.log(f"\nINCOMPLETO: faltan en GitHub {self.faltan}. Los workflows no podrán correr hasta resolverlo.")
                return 1
            self.log("\nListo: Oracle y GitHub quedaron configurados. El despliegue se hace con el workflow desplegar-pruebas.")
            return 0
        except ErrorPrecondicion as e:
            print(f"ABORTADO (2): {self.limpiar(e)}", file=sys.stderr)
            self.parcial()
            return 2
        except KeyboardInterrupt:
            print("INTERRUMPIDO (1).", file=sys.stderr)
            self.parcial()
            return 1
        except Exception as e:  # noqa: BLE001 - cualquier error inesperado termina con codigo 1 y sin datos sensibles
            print(f"ERROR (1): {e.__class__.__name__}: {self.limpiar(e)}", file=sys.stderr)
            self.parcial()
            return 1
        finally:
            self.limpiar_tmp()

    def limpiar_tmp(self):
        if self.s3_pendiente:
            print(f"ATENCIÓN: la llave S3 '{N_LLAVE_S3}' se creó pero su secreto no llegó a GitHub y no se puede releer: bórrala en la "
                  "consola (Mi perfil > Llaves secretas del cliente) y vuelve a ejecutar apply.", file=sys.stderr)
        if not self.tmp or not self.tmp.exists():
            return
        if self.priv_pendiente:
            print(f"ATENCIÓN: conservé el directorio temporal {self.tmp} porque guarda la llave privada del usuario técnico que no llegó a "
                  f"GitHub (huella {self.huella or 'aún sin subir'}). Si vuelves a ejecutar apply se generará otra llave de API: borra la huérfana "
                  "en la consola y este directorio cuando termines.", file=sys.stderr)
            return
        shutil.rmtree(self.tmp, ignore_errors=True)
        if self.tmp.exists():
            print(f"AVISO: no pude borrar el directorio temporal {self.tmp}; bórralo a mano.", file=sys.stderr)


def crear_parser():
    comun = argparse.ArgumentParser(add_help=False)
    comun.add_argument("--config", required=True, help="archivo de configuración OCI del administrador (perfil DEFAULT; sirve el que pega la consola)")
    comun.add_argument("--clave-admin", required=True, help="ruta de la llave privada .pem del administrador (se monta de solo lectura)")
    comun.add_argument("--repo-infra", default=REPO_INFRA, help="repositorio de GitHub que recibe secretos y variables (por defecto %(default)s)")
    comun.add_argument("--salida", default="salida-oci", help="carpeta para resultado.json, solo con identificadores (por defecto %(default)s)")
    ap = argparse.ArgumentParser(prog="bootstrap_oci.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    comun.add_argument("--sobrescribir-secretos", action="store_true",
                       help="permite reemplazar secretos y variables que ya existen en el repositorio (en plan solo cambia lo que se muestra)")
    comun.add_argument("--omitir-prueba", action="append", default=[], choices=["N1", "N2", "N4", "N6", "N7"], metavar="ID",
                       help="omite una prueba NEGATIVA (N1, N2, N4, N6 o N7) cuya expectativa no se pudo verificar sin cuenta; queda como OMITIDA en resultado.json")
    sub = ap.add_subparsers(dest="orden", required=True)
    sub.add_parser("plan", parents=[comun], help="solo lectura: muestra qué se crearía; nunca crea ni modifica nada")
    sub.add_parser("apply", parents=[comun], help="crea lo que falte (idempotente), verifica y carga GitHub si todo pasa")
    return ap


def main(argv=None, ejecutar=None, dormir=None):
    return Arranque(crear_parser().parse_args(argv), ejecutar, dormir).correr()


if __name__ == "__main__":
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(encoding="utf-8", errors="replace")  # misma codificacion en consola y en tuberias de Windows
    sys.exit(main())
