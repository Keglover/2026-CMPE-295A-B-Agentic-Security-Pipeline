#!/usr/bin/env bash
curl -s http://localhost:11434/api/generate \
  -H 'Content-Type: application/json' \
  -d '{"model":"kimi-k2.5:cloud","prompt":"What is gVisor and why does it improve container security?","stream":false}' \
  | python3 -m json.tool