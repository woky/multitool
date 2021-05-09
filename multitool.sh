#!/bin/sh
PYTHONPATH="$(dirname "$0"):$PYTHONPATH" exec python3 -m multitool.main "$@"
