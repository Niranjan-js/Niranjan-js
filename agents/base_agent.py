from abc import ABC, abstractmethod

class BaseAgent(ABC):
    def __init__(self, name: str = "BaseAgent"):
        self.name = name

    @abstractmethod
    async def analyze(self, data: str):
        pass