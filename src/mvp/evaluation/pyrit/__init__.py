import asyncio
from pyrit.setup import initialize_pyrit_async
from pyrit.setup.initializers import ScorerInitializer, TargetInitializer

await initialize_pyrit_async(memory_db_type="InMemory", initializers=[TargetInitializer(), ScorerInitializer()])