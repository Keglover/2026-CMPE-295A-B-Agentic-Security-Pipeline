# How to run the evaluation script
First, spin up the docker container and go into the terminal
From the /src/mvp directory, run the commmand ```python -m scenarios.run_scenarios```
Note that you might need to run ```uvicode.exe app.main:app --reload``` to reboot the container, even if you just started the container. I don't know why this happens, and I'm kind of worried this might lead to issues later down the line.