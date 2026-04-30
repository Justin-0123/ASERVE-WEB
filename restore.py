#!/usr/bin/env python
import os
import sys
import sqlite3
import zipfile
import tempfile
import shutil
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.getcwd())

from app import app

# Manually define and execute the restore backup logic
zip_path = "backups/respaldo_aserve_2026-04-28_23-02-05.zip"

with app.app_context():
    # Validate ZIP exists
    if not os.path.exists(zip_path):
        print("❌ El archivo ZIP no existe.")
        print(f"Ruta recibida: {zip_path}")
        sys.exit(1)

    # Validate ZIP format
    if not zipfile.is_zipfile(zip_path):
        print("❌ El archivo indicado no es un ZIP válido.")
        sys.exit(1)

    # Prepare paths
    db_path = app.config["DATABASE"]
    db_folder = os.path.dirname(db_path)
    upload_folder = app.config["UPLOAD_FOLDER"]

    if not os.path.isabs(upload_folder):
        upload_folder = os.path.join(os.getcwd(), upload_folder)

    os.makedirs(db_folder, exist_ok=True)
    os.makedirs(upload_folder, exist_ok=True)

    fecha_restore = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Create emergency backup
    backup_folder = os.path.join(os.getcwd(), "backups")
    os.makedirs(backup_folder, exist_ok=True)

    pre_backup_path = os.path.join(
        backup_folder,
        f"pre_restore_aserve_{fecha_restore}.zip"
    )

    print("🟡 Creando respaldo de emergencia antes de restaurar...")

    with zipfile.ZipFile(pre_backup_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
        # Backup current DB
        if os.path.exists(db_path):
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_db:
                temp_db_path = temp_db.name

            try:
                source = sqlite3.connect(db_path)
                destination = sqlite3.connect(temp_db_path)

                with destination:
                    source.backup(destination)

                source.close()
                destination.close()

                zip_file.write(
                    temp_db_path,
                    arcname="database/aserve.db"
                )

            finally:
                if os.path.exists(temp_db_path):
                    os.remove(temp_db_path)

        # Backup current uploads
        if os.path.exists(upload_folder):
            for root, dirs, files in os.walk(upload_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, upload_folder)
                    zip_name = os.path.join("uploads", relative_path)
                    zip_file.write(file_path, arcname=zip_name)

        info = f"""RESPALDO DE EMERGENCIA ASERVE
Fecha: {fecha_restore}

Este respaldo fue creado automáticamente antes de restaurar otro respaldo.

Contenido:
- database/aserve.db
- uploads/
"""
        zip_file.writestr("LEEME_PRE_RESTORE.txt", info)

    print(f"✅ Respaldo de emergencia creado: {pre_backup_path}")

    # Extract backup ZIP
    with tempfile.TemporaryDirectory() as temp_dir:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        restored_db = os.path.join(temp_dir, "database", "aserve.db")
        restored_uploads = os.path.join(temp_dir, "uploads")

        # Validate backup has database
        if not os.path.exists(restored_db):
            print("❌ El respaldo no contiene database/aserve.db.")
            print("No se restauró nada.")
            print(f"Tu respaldo de emergencia quedó en: {pre_backup_path}")
            sys.exit(1)

        # Restore database
        print("🟡 Restaurando base de datos...")

        if os.path.exists(db_path):
            os.remove(db_path)

        shutil.copy2(restored_db, db_path)
        print("✅ Base de datos restaurada correctamente.")

        # Restore uploads
        print("🟡 Restaurando imágenes...")

        if os.path.exists(upload_folder):
            shutil.rmtree(upload_folder)

        if os.path.exists(restored_uploads):
            shutil.copytree(restored_uploads, upload_folder)
            print("✅ Imágenes restauradas correctamente.")
        else:
            os.makedirs(upload_folder, exist_ok=True)
            print("⚠️ El respaldo no tenía carpeta uploads. Se creó vacía.")

    print("")
    print("✅ RESTAURACIÓN COMPLETADA CORRECTAMENTE")
    print(f"Respaldo restaurado: {zip_path}")
    print(f"Respaldo de emergencia previo: {pre_backup_path}")
    print("")
    print("Ahora podés iniciar Flask nuevamente con:")
    print("python app.py")
