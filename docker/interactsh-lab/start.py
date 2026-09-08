"""Ephemeral TLS/auth setup for the local-only, real Interactsh server fixture."""
import os
from pathlib import Path
import socket
import subprocess

Path("/tmp/interactsh").mkdir(mode=0o700)
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", "/tmp/interactsh/key.pem", "-out", "/tmp/interactsh/cert.pem", "-subj", "/CN=oast.test",
                "-addext", "subjectAltName=DNS:oast.test,DNS:*.oast.test"], check=True, capture_output=True)
config = Path("/tmp/interactsh/config.yaml")
config.write_text('token: "erlik-isolated-lab-token"\n')
config.chmod(0o600)
ip = socket.gethostbyname(socket.gethostname())
# Supplying -ip prevents upstream public-IP discovery; custom cert/key prevent
# ACME issuance. No ports are published by the acceptance test.
os.execv("/usr/local/bin/interactsh-server", ["interactsh-server", "-d", "oast.test", "-ip", ip,
         "-lip", "0.0.0.0", "-cert", "/tmp/interactsh/cert.pem", "-privkey", "/tmp/interactsh/key.pem",
         "-config", str(config), "-duc"])
