import logging
import argparse
import json
import os

from dataclasses import asdict, dataclass
from httpx import main
from datetime import datetime, timezone
from pathlib import Path
from mvp.agent.config import PIPELINE_URL

def main() -> None:
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting benchmark...")
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", type=str, help="")
    parser.add_argument("--task", type=str, help="")
    parser.add_argument("--endpoint", default=PIPELINE_URL)
    parser.add_argument("--model", default="llama3.1")  # Check here if there is a default model type
    parser.add_argument("--attack", choices=["direct", "indirect"], default="direct")   # TODO: Need to check with others if we even handle IPI - don't think we do?
    parser.add_argument("--mode", type=str, help="")
    args = parser.parse_args()

if __name__ == "__main__":
    main()