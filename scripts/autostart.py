"""Crea la tarea de autoarranque por usuario (sin admin) en Windows.

Equivale a poner el ejecutable en la carpeta Startup, pero mas
robusto y facil de inspeccionar.

Uso:
    python -m localapi.scripts.autostart install
    python -m localapi.scripts.autostart remove
    python -m localapi.scripts.autostart status
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path


TASK_NAME = "GadSignLocalAPIAutoStart"


def _schtasks(*args: str) -> int:
    return subprocess.call(["schtasks", *args])


def _python_exe() -> str:
    """Resuelve el ejecutable de Python actual."""
    return sys.executable


def _entrypoint() -> list:
    return [_python_exe(), "-m", "localapi.main"]


def install() -> int:
    if os.name != "nt":
        print("Autoarranque solo Windows.")
        return 1
    _schtasks(
        "/Delete", "/TN", TASK_NAME, "/F",
    )
    cmd = " ".join(shlex.quote(p) for p in _entrypoint())
    xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>GadSign Local API - inicio por usuario al iniciar sesion.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-4-3</GroupId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions>
    <Exec>
      <Command>{_entrypoint()[0]}</Command>
      <Arguments>{" ".join(_entrypoint()[1:])}</Arguments>
      <WorkingDirectory>{Path.cwd()}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"""
    xml_path = Path(os.environ["TEMP"]) / "gadsign_localapi_task.xml"
    xml_path.write_text(xml, encoding="utf-16")
    rc = _schtasks(
        "/Create",
        "/TN", TASK_NAME,
        "/XML", str(xml_path),
        "/F",
    )
    if rc == 0:
        print(f"Tarea creada: {TASK_NAME}")
    else:
        print(f"No se pudo crear la tarea (rc={rc}). Revise permisos.")
    return rc


def remove() -> int:
    if os.name != "nt":
        return 1
    rc = _schtasks("/Delete", "/TN", TASK_NAME, "/F")
    print("Tarea eliminada." if rc == 0 else f"No se elimino (rc={rc}).")
    return rc


def status() -> int:
    if os.name != "nt":
        return 1
    return _schtasks("/Query", "/TN", TASK_NAME, "/V", "/FO", "LIST")


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[1].lower()
    if cmd == "install":
        return install()
    if cmd == "remove":
        return remove()
    if cmd == "status":
        return status()
    print("Comando no reconocido. Use: install | remove | status")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
