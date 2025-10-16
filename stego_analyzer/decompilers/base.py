import abc

class Decompiler(abc.ABC):
    """
    Abstract base class for a decompiler.
    """

    @abc.abstractmethod
    def decompile(self, binary_path: str, output_dir: str) -> str:
        """
        Decompiles the binary at the given path and returns the path to the decompiled C code.
        """
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        Returns the name of the decompiler.
        """
        raise NotImplementedError