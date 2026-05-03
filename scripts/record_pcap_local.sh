#!/usr/bin/env bash
# Rekam lalu lintas TCP ke Flask (default loopback port 5001) untuk bukti PCAP.
# Penggunaan: ./scripts/record_pcap_local.sh [PORT] [keluaran.pcap]
# Hentikan dengan Ctrl+C setelah batch selesai. Lihat METODOLOGI_FORENSIK_JARINGAN.md.
set -euo pipefail
PORT="${1:-5001}"
OUT="${2:-capture_batch.pcap}"
echo "Menyimpan ke ${OUT} (interface lo, filter tcp port ${PORT}). Ctrl+C untuk berhenti."
exec sudo tcpdump -i lo -w "${OUT}" "tcp port ${PORT}"
