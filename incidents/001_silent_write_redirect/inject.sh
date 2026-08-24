#!/usr/bin/env sh
# Thin wrapper: the spec (7.1, 11.1) names this file. See DECISIONS.md D-005.
exec python -m incidents.inject 001 "$@"
