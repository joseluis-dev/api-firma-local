"""Aislamiento global de la suite: nunca tocar el perfil real del usuario.

``config_store`` y ``pairing_manager`` son singletons que leen/escriben bajo
``LOCALAPI_DATA_DIR`` al importarse el paquete. Se apunta a un directorio
temporal ANTES de que cualquier test importe ``localapi``.
"""
import atexit
import os
import shutil
import tempfile

_DATA_DIR = tempfile.mkdtemp(prefix="localapi-tests-")
os.environ["LOCALAPI_DATA_DIR"] = _DATA_DIR
atexit.register(shutil.rmtree, _DATA_DIR, ignore_errors=True)
