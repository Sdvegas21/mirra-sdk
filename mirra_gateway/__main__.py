"""Run the gateway:  python -m mirra_gateway --config gateway.json [--port 8420]

Config format (keys are stored HASHED — see mirra_gateway.hash_api_key):

    {
      "base_home": "~/.mirra-gateway",
      "tenants": [{"tenant_id": "acme", "key_hash": "<sha256 of the api key>"}],
      "profile": "prod_locked",
      "mission_control": {"url": "http://127.0.0.1:3000/api/tasks", "api_key_env": "MC_API_KEY"}
    }
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .mission_control import MissionControlEmitter
from .server import GatewayServer, make_server
from .tenants import TenantRegistry


def main() -> int:
    parser = argparse.ArgumentParser(prog="mirra_gateway")
    parser.add_argument("--config", required=True, help="path to gateway JSON config")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8420)
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    registry = TenantRegistry.from_config(args.config)

    mission_control = None
    mc_config = config.get("mission_control")
    if mc_config:
        api_key = os.environ.get(mc_config.get("api_key_env", "MC_API_KEY"), "")
        if api_key:
            mission_control = MissionControlEmitter(mc_config["url"], api_key)

    gateway = GatewayServer(
        registry,
        profile=config.get("profile", "prod_locked"),
        mission_control=mission_control,
    )
    server = make_server(gateway, host=args.host, port=args.port)
    print(f"mirra-gateway serving contract v1 on http://{args.host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
