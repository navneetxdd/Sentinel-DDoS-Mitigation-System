# Reflection signatures (optional)

The pipeline can load a reflection-signature JSON file for protocol/port and payload-pattern hints. By default it looks for `signatures/methods.json` in the project root (override with `SENTINEL_SIGNATURES_FILE` or `SENTINEL_REFLECTION_PORTS_FILE`).

Place a compatible JSON file here (e.g. named `methods.json`) with structure such as:

- `spoofed_ip_attacks`, `valid_ip_attacks`, `other_attacks` (or similar) mapping attack names to hex or `protocol\t\tport` patterns.

See the main project README under "Signature feed integration option" for environment variables and format details.
