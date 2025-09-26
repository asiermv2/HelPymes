#!/bin/bash
# GUI mínima con zenity para tu script de escaneo

# Pedir host
HOST=$(zenity --entry --title="Escaneo" --text="Host (IP o dominio):")
[ -n "$HOST" ] || { zenity --error --text="Host requerido"; exit 1; }

# Pedir nombre de archivo base
OUT=$(zenity --entry --title="Escaneo" --text="Nombre base de fichero de salida (sin .txt):")
[ -n "$OUT" ] || { zenity --error --text="Nombre requerido"; exit 1; }

# Confirmar y ejecutar
if zenity --question --text="Ejecutar escaneo de vulnerabilidades a $HOST y guardar en ${OUT}_* ?"; then
	(
		./scan.sh $HOST $OUT
	) | zenity --text-info --title="Output del scan..." --width=800 --height=600
fi

