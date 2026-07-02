"""Window-level native confirmation dialogs.

Uses tkinter for cross-platform modal windows. On Windows, the
window is forced to topmost and a brief detail panel is shown.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional, Tuple

from ..errors import UserCancelledError


log = logging.getLogger(__name__)


def _run_modal(creator) -> None:
    """Runs a tkinter Toplevel modally on the main thread."""
    import tkinter as tk
    from tkinter import ttk

    root = creator()
    if root is None:
        return
    root.transient()
    root.grab_set()
    root.focus_force()
    root.attributes("-topmost", True)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()


def _approval_window(
    title: str,
    message: str,
    details: str,
    approve_label: str = "Aprobar",
    deny_label: str = "Denegar",
) -> Optional[bool]:
    """Returns True if approved, False if denied, None if dialog crashed."""
    import tkinter as tk
    from tkinter import ttk

    result: dict = {"value": None}
    error: dict = {}

    def _close(root, value):
        result["value"] = value
        try:
            root.grab_release()
        except Exception:
            pass
        root.destroy()

    def build() -> tk.Tk:
        try:
            root = tk.Tk()
        except Exception as exc:
            error["exc"] = exc
            return None
        root.title(title)
        root.geometry("560x420")
        root.minsize(520, 380)
        root.resizable(True, True)

        header = ttk.Frame(root, padding=(16, 12))
        header.pack(fill="x")
        ttk.Label(
            header,
            text=title,
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            header,
            text=message,
            wraplength=520,
            justify="left",
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(6, 0))

        body = ttk.Frame(root, padding=(16, 8))
        body.pack(fill="both", expand=True)

        text = tk.Text(
            body,
            wrap="word",
            height=12,
            font=("Consolas", 9),
            background="#fafafa",
        )
        text.insert("1.0", details)
        text.configure(state="disabled")
        scroll = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        actions = ttk.Frame(root, padding=(16, 12))
        actions.pack(fill="x")
        ttk.Button(
            actions,
            text=deny_label,
            command=lambda: _close(root, False),
        ).pack(side="right", padx=(8, 0))
        ttk.Button(
            actions,
            text=approve_label,
            command=lambda: _close(root, True),
        ).pack(side="right")

        root.bind("<Return>", lambda _e: _close(root, True))
        root.bind("<Escape>", lambda _e: _close(root, False))

        return root

    t = threading.Thread(target=_run_modal, args=(build,), daemon=True)
    t.start()
    t.join(timeout=180)
    if error:
        log.warning("approval window fallo: %s", error["exc"])
        return None
    return result["value"]


def ask_pairing_approval(origin: str, scopes) -> Optional[bool]:
    details_lines = [
        f"Origen:   {origin}",
        "",
        "Scopes solicitados:",
    ]
    for s in scopes or []:
        details_lines.append(f"  - {s}")
    details_lines.append("")
    details_lines.append(
        "Si aprueba, este origen podra usar GadSign Local API hasta que "
        "usted revoque el permiso o se cierre la sesion."
    )
    return _approval_window(
        title="Emparejamiento de origen",
        message=f"El origen {origin} solicita acceso a GadSign Local API.",
        details="\n".join(details_lines),
        approve_label="Permitir",
        deny_label="Denegar",
    )


def ask_signature_confirmation(
    origin: str,
    cert_subject: str,
    cert_serial: str,
    document_sha256: str,
    razon: str,
    page: int,
) -> Optional[bool]:
    details = (
        f"Origen:    {origin}\n"
        f"Certificado (CN):  {cert_subject}\n"
        f"Certificado (Serial): {cert_serial}\n"
        f"Documento SHA-256: {document_sha256}\n"
        f"Razon:     {razon}\n"
        f"Pagina:    {page}\n"
        "\n"
        "Verifique que el documento y el certificado son correctos.\n"
        "Presione el token fisicamente cuando el LED parpadee (Touch Sense).\n"
    )
    return _approval_window(
        title="Solicitud de firma digital",
        message=(
            f"El origen {origin} solicita firmar un documento. "
            "Revise los detalles y confirme."
        ),
        details=details,
        approve_label="Firmar",
        deny_label="Cancelar",
    )
