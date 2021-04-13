import asyncio
import functools
from asyncio import Task
from typing import Callable, Coroutine

import nest_asyncio


def to_sync(as_task: bool = True):
    """
    A better implementation of `asyncio.run`.

    :param as_task: Forces the future to be scheduled as task (needed for e.g. aiohttp).

    Link: https://stackoverflow.com/a/63593888
    """

    def _run_async(func: Callable[..., Coroutine]):
        """
        :param func: A function that return future or task or call of an async method.
        :return: wrapped function
        """

        @functools.wraps(func)
        def func_wrapper(*args, **kwargs):
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:  # no event loop running:
                loop = asyncio.new_event_loop()
                return loop.run_until_complete(
                    _to_task(func(*args, **kwargs), as_task, loop)
                )
            else:
                nest_asyncio.apply(loop)
                return asyncio.run(_to_task(func(*args, **kwargs), as_task, loop))

        return func_wrapper

    return _run_async


def _to_task(future, as_task, loop):
    if not as_task or isinstance(future, Task):
        return future
    return loop.create_task(future)
