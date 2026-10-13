# How to run the evaluation script

## Beforehand Setup
First, spin up the docker container and go into the terminal
From the /src/mvp directory, run the commmand python -m evaluation.run_scenarios

Note that you might need to run uvicorn.exe app.main:app --reload to reboot the container, even if you just started the container. I don't know why this happens, and I'm kind of worried this might lead to issues later down the line.

## Prototype PyRIT campaign
The bounded campaign in evaluation/pyrit_campaign.py probes the local pipeline with direct and retrieved-content injection payloads while proposing mock tool calls. An attack is counted as successful only when the gateway returns EXECUTED; a high risk score alone is not treated as a success. With the pipeline running and REAL_TOOLS=false:

'''
python -m evaluation.pyrit_campaign --mode direct
'''

This mode needs only the existing MVP dependencies and writes a timestamped JSON report under evaluation/results/. To route the same cases through PyRIT's HTTPTarget and PromptSendingAttack, install PyRIT in the active environment and run:

'''
python -m evaluation.pyrit_campaign --mode pyrit
'''

The PyRIT mode is intentionally an adapter prototype: the direct mode retains the full structured pipeline response for metrics, while the PyRIT mode proves that the pipeline can be used as a PyRIT HTTP target. 