import functools

from .path import Path


class AbstractPolicy(object):
    """
    A policy implements all routing decisions by
    providing comparison methods for interfaces
    and paths
    """
    name = NotImplemented

    def __init__(self):
        if self.name == NotImplemented:
            raise NotImplementedError("The policy needs a name")

    @staticmethod
    def with_path_cache(func):
        @functools.wraps(func)
        def wrapper(self, path):
            if self.name in path.policy_cache:
                return path.policy_cache[self.name]

            metric = func(self, path)
            path.policy_cache[self.name] = metric
            return metric

        return wrapper

    def path_cmp_key(self, path: Path):
        """
        returns a sort key e.g. for the `sorted` function
        lower is better
        """
        raise NotImplementedError("A policy must override this method")


class SimpleLossPolicy(AbstractPolicy):
    """
    Route via the lowest-loss path
    """
    name = 'lowest-loss'

    @staticmethod
    def _acc_loss(path: Path) -> int:
        loss = 0
        for link in path.links:
            loss += path.attributes[link]['loss']
        return loss

    @AbstractPolicy.with_path_cache
    def path_cmp_key(self, path: Path) -> int:
        return self._acc_loss(path)


class SimpleBandwidthPolicy(AbstractPolicy):
    """
    Route via the highest-bandwidth path
    """
    name = 'highest-bandwidth'

    @staticmethod
    def _acc_bw(path: Path) -> int:
        return min(path.attributes[link]['bandwidth'] for link in path.links)

    @AbstractPolicy.with_path_cache
    def path_cmp_key(self, path: Path) -> float:
        # the minimum bandwidth of the path while slightly preferring
        # shorter paths
        return - self._acc_bw(path) * (0.99 ** len(path.links))
