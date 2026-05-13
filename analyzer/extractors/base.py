from abc import ABC, abstractmethod


class BaseExtractor(ABC):

    @abstractmethod
    def extract(
            self,
            flat_api,
            func,
    ):
        pass