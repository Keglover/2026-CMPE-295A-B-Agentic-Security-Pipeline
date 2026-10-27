# How to run the AgentDojo benchmarking script

## Beforehand Setup
First, spin up the docker container and go into the terminal
From the /src/mvp directory, run the commmand python -m evaluation.run_scenarios

Note that you might need to run uvicorn.exe app.main:app --reload to reboot the container, even if you just started the container.

Also, be sure to run the command "pythton -m pip install agentdojo" to make sure you have the necessary modules on your machine before attempting to run the benchmark, otherwise you will get errors!