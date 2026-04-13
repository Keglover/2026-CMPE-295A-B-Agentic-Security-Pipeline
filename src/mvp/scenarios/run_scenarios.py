"""
Scenario runner for the Agentic Security Pipeline.

Loads scenario JSON files, POSTs each one to the pipeline, and compares
the response against the _expected block defined in each file.

Usage (from src/mvp/):
    python -m scenarios.run_scenarios

The pipeline server must be running before executing this script:
    uvicorn app.main:app --reload
"""

from __future__ import annotations

import json
import logging
import sys
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx

from agent.config import PIPELINE_URL

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s — %(message)s",
)
_log = logging.getLogger("run_scenarios")

# ---------------------------------------------------------------------------
# Derive sibling endpoint URLs from PIPELINE_URL
# e.g. http://localhost:8000/pipeline → http://localhost:8000
# ---------------------------------------------------------------------------

_parsed = urlparse(PIPELINE_URL)
BASE_URL: str = f"{_parsed.scheme}://{_parsed.netloc}"
HEALTH_URL: str = f"{BASE_URL}/health"
TOOLS_URL: str = f"{BASE_URL}/tools"

SCENARIOS_DIR: Path = Path(__file__).resolve().parent / "json files"

# ---------------------------------------------------------------------------
# Endpoint connections
# ---------------------------------------------------------------------------


def check_health() -> bool:
    """
    GET /health — confirm the pipeline server is reachable and alive.

    Returns:
        True if the server responds with status ok, False otherwise.
    """
    _log.info("Checking pipeline health at %s", HEALTH_URL)
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(HEALTH_URL)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "ok":
                _log.info("Pipeline is healthy (version=%s)", data.get("version", "?"))
                return True
            _log.error("Unexpected health response: %s", data)
            return False
    except httpx.ConnectError:
        _log.error(
            "Cannot reach pipeline at %s — is the server running?", BASE_URL
        )
        return False
    except httpx.HTTPStatusError as exc:
        _log.error("Health check returned HTTP %d", exc.response.status_code)
        return False


def fetch_allowed_tools() -> set[str]:
    """
    GET /tools — retrieve the set of tool names the gateway will permit.

    Used to pre-validate scenario files before sending them to the pipeline,
    so a misconfigured proposed_tool fails early with a clear error rather
    than silently producing a DENIED gateway result.

    Returns:
        Set of allowed tool name strings, or empty set on failure.
    """
    _log.info("Fetching allowed tools from %s", TOOLS_URL)
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(TOOLS_URL)
            resp.raise_for_status()
            data = resp.json()
            tools = set(data.get("allowed_tools", {}).keys())
            _log.info("Allowed tools: %s", sorted(tools))
            return tools
    except httpx.ConnectError:
        _log.error("Cannot reach /tools endpoint")
        return set()
    except httpx.HTTPStatusError as exc:
        _log.error("/tools returned HTTP %d", exc.response.status_code)
        return set()


def run_scenario(payload: dict) -> dict | None:
    """
    POST /pipeline — submit a single scenario payload and return the response.

    The _expected block must be stripped from the payload before calling this.

    Args:
        payload: A PipelineRequest-shaped dict (no _expected, no _comment).

    Returns:
        The full PipelineResponse dict, or None if the request failed.
    """
    request_id = payload.get("request_id", "<auto>")
    _log.info("POSTing scenario request_id=%s to %s", request_id, PIPELINE_URL)
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(PIPELINE_URL, json=payload)
            resp.raise_for_status()
            return resp.json()
    except httpx.ConnectError:
        _log.error("Cannot reach pipeline at %s", PIPELINE_URL)
        return None
    except httpx.HTTPStatusError as exc:
        _log.error(
            "Pipeline returned HTTP %d: %s",
            exc.response.status_code,
            exc.response.text[:200],
        )
        return None

# ---------------------------------------------------------------------------
# Data loading - getting scenario files into the workflow. DOES NOT trim _expected fields
# ---------------------------------------------------------------------------
def loadData(loadBenign=True, loadMalicious=True):
    _log.info("=== Loading Scenario Data ===")
    _log.info("Function passed with loadBenign=%s, loadmalicious=%s", loadBenign, loadMalicious)

    benignScenarios, malScenarios = None, None

    if loadBenign is True:
        benignScenarios = []
    
        _log.info("Loading benign scenario files")
        with os.scandir(SCENARIOS_DIR / "Benign") as scenarios:
            for scenario in scenarios:
                if scenario.is_file():
                    _log.info("Found scenario %s", scenario.name)
                    benignScenarios.append(scenario)

    if loadMalicious is True:
        malScenarios = []

        _log.info("Loading malicious scenario files")
        with os.scandir(SCENARIOS_DIR / "Malicious") as scenarios:
            for scenario in scenarios:
                if scenario.is_file():
                    _log.info("Found scenario %s", scenario.name)
                    malScenarios.append(scenario)

    return benignScenarios, malScenarios
    
def processScenarios():
    benignScenarios, maliciousScenarios = loadData()
    
    benignResponses = {}
    benignExpected = {}

    maliciousResponses = {}
    maliciousExpected = {}

    if benignScenarios is not None:
        _log.info("=== Executing bengin scenarios ===")
        for scenarioFile in benignScenarios:
            with open(scenarioFile.path, 'r') as file:
                rawScenario = json.load(file)

            expectedResponse = rawScenario.pop("_expected", {})
            rawScenario.pop("_comment", None)
        
            if not rawScenario.get("content"):
                _log.warning("Skipping %s scenario file - No content provided.", scenarioFile.name)
                continue
            
            response = run_scenario(rawScenario)

            if response is None:
                _log.error("No response given for %s", scenarioFile.name)
                continue
            
            benignExpected[scenarioFile.name] = expectedResponse
            benignResponses[scenarioFile.name] = response

        _log.info("=== End benign scenario execution ===")
    else:
        _log.warning("No benign scenarios specified. If this is unintended, something may have gone wrong in prior functions.")

    if maliciousScenarios is not None:
        _log.info("=== Executing malicious scenarios ===")
        for scenarioFile in maliciousScenarios:
            with open(scenarioFile.path, 'r') as file:
                rawScenario = json.load(file)

            expectedResponse = rawScenario.pop("_expected", {})
            rawScenario.pop("_comment", None)
        
            if not rawScenario.get("content"):
                _log.warning("Skipping %s scenario file - No content provided.", scenarioFile.name)
                continue
            
            response = run_scenario(rawScenario)
            
            if response is None:
                _log.error("No response given for %s", scenarioFile.name)
                continue
            
            maliciousExpected[scenarioFile.name] = expectedResponse
            maliciousResponses[scenarioFile.name] = response

        _log.info("=== End malicious scenario execution ===")
    else:
        _log.warning("No malicious scenarios specified. If this is unintended, something may have gone wrong in prior functions.")

## Responses have been gathered, now we ouptut them systematically

    _log.info("=== Begin log analysis ===")

    benignPassed, benignFailed, skipBenign = {}, {}, False
    if benignScenarios is not None:
        for scenarioFile in benignScenarios:
            if scenarioFile.name not in benignResponses:
                _log.warning(f"Skipping analysis for {scenarioFile.name} - no response recorded")
                continue
            
            scenarioResponse = benignResponses[scenarioFile.name]
            scenarioResponseExpected = benignExpected[scenarioFile.name]
            p, f = responseAnalysis(scenarioResponse, scenarioResponseExpected, scenarioFile.name)

            for key in p:   # Accumulate the results
                benignPassed.setdefault(key, []).extend(p[key])
                benignFailed.setdefault(key, []).extend(f[key])
    else:
        _log.warning("No benign scenarios. Skipping analysis of benign scenarios.")
        skipBenign = True

    malPassed, malFailed, skipMalicious = {}, {}, False
    if maliciousScenarios is not None:
        for scenarioFile in maliciousScenarios:
            if scenarioFile.name not in maliciousResponses:
                _log.warning(f"Skipping analysis for {scenarioFile.name} - no response recorded")
                continue
            
            scenarioResponse = maliciousResponses[scenarioFile.name]
            scenarioResponseExpected = maliciousExpected[scenarioFile.name]
            p, f = responseAnalysis(scenarioResponse, scenarioResponseExpected, scenarioFile.name)

            for key in p:
                malPassed.setdefault(key, []).extend(p[key])
                malFailed.setdefault(key, []).extend(f[key])
    else:
        _log.warning("No malicious scenarios. Skipping analysis of malicious scenarios.")
        skipMalicious = True

    def aggregate(analysis):
        numPolicy, numGateway, numRisk = 0, 0, 0

        for key in analysis.keys():
            for a in analysis[key]:
                name, output = a
                outstr = f"Scenario: {name} | Output: {output}"
                _log.info(outstr)

                if key == "policy_action":
                    numPolicy += 1
                if key == "gateway_decision":
                    numGateway += 1
                if key == "risk_score":
                     numRisk += 1

        return numPolicy, numGateway, numRisk

    _log.info("=== Log analysis results ===")
    _log.info("Passed:")

    b_numPassed_policy, b_numPassed_gateway, b_numPassed_risk = (aggregate(benignPassed) if benignPassed or not skipBenign else -1, -1, -1)
    m_numPassed_policy, m_numPassed_gateway, m_numPassed_risk = (aggregate(malPassed)    if malPassed or not skipMalicious else -1, -1, -1)

    _log.info("Failed:")

    b_numFailed_policy, b_numFailed_gateway, b_numFailed_risk = (aggregate(benignFailed) if benignFailed or not skipBenign else -1, -1, -1)
    m_numFailed_policy, m_numFailed_gateway, m_numFailed_risk = (aggregate(malFailed)    if malFailed or not skipMalicious else -1, -1, -1)

    _log.info("Statistics: (-1 indicates a skipped field)")

    _log.info("policy_action:")
    _log.info(f"Benign PASS: {b_numPassed_policy}    | Benign FAIL: {b_numFailed_policy}")
    _log.info(f"Malicious PASS: {m_numPassed_policy} | Malicious FAIL: {m_numFailed_policy}")

    _log.info("gateway_decision:")
    _log.info(f"Benign PASS: {b_numPassed_gateway}    | Benign FAIL: {b_numFailed_gateway}")
    _log.info(f"Malicious PASS: {m_numPassed_gateway} | Malicious FAIL: {m_numFailed_gateway}")

    _log.info("risk_score:")
    _log.info(f"Benign PASS: {b_numPassed_risk}    | Benign FAIL: {b_numFailed_risk}")
    _log.info(f"Malicious PASS: {m_numPassed_risk} | Malicious FAIL: {m_numFailed_risk}")

# ---------------------------------------------------------------------------
# Helper function to analyze responses
# ---------------------------------------------------------------------------
def responseAnalysis(result, expected, scenarioName):
    passed = {"policy_action": [], "gateway_decision": [], "risk_score": []}
    failed = {"policy_action": [], "gateway_decision": [], "risk_score": []}

    result_PolicyAction     = result["policy"]["policy_action"]
    result_GatewayDecision  = result["gateway"]["gateway_decision"] if result["gateway"] else None
    result_RiskScore        = result["risk"]["risk_score"]

    expected_PolicyAction       = expected.get("policy_action")
    expected_GatewayDecision    = expected.get("gateway_decision")
    expected_RiskScore          = expected.get("max_risk_score")

    def check(checkRes, checkExpec, index):
        if index == "risk_score":   # Risk score uses a slightly differnet schema than the others
            if checkRes is None or checkRes <= checkExpec:
                outputString = f"PASS [{scenarioName}] {index}: {checkRes} <= {checkExpec}"
                _log.info(outputString)
                passed[index].append((scenarioName, outputString))
            else:
                outputString = f"FAIL [{scenarioName}] {index}: expected<={checkExpec}, result={checkRes}"
                _log.info(outputString)
                failed[index].append((scenarioName, outputString))

        else:                       # For every other metric
            if checkRes == checkExpec:
                outputString = f"PASS [{scenarioName}] {index}: {checkRes}"
                _log.info(outputString)
                passed[index].append((scenarioName, outputString))
            else:
                outputString = f"FAIL [{scenarioName}] {index}: expected={checkExpec}, result={checkRes}"
                _log.warning(outputString)
                failed[index].append((scenarioName, outputString))

    _log.info("Responses v Expectations for %s as follows:", scenarioName)
    check(result_PolicyAction,      expected_PolicyAction,      "policy_action")
    check(result_GatewayDecision,   expected_GatewayDecision,   "gateway_decision")
    check(result_RiskScore,         expected_RiskScore,         "risk_score")
    _log.info("End Responses v Expectations for %s.", scenarioName)

    return passed, failed

# ---------------------------------------------------------------------------
# Entry point — basic connectivity smoke test
# ---------------------------------------------------------------------------

def healthCheck():
    _log.info("=== Scenario Runner starting ===")
    _log.info("Base URL : %s", BASE_URL)
    _log.info("Scenarios: %s", SCENARIOS_DIR)

    # Step 1: health gate — abort immediately if server is down
    if not check_health():
        _log.error("Aborting — pipeline server is not available.")
        sys.exit(1)

    # Step 2: fetch allowed tools for later pre-validation
    allowed_tools = fetch_allowed_tools()
    if not allowed_tools:
        _log.warning("Could not retrieve allowed tools — skipping pre-validation.")

    _log.info("=== Endpoint connections OK — ready to run scenarios ===")

if __name__ == "__main__":
    #healthCheck()
    processScenarios()