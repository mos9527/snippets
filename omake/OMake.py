"""OMake - pOrtable Make framework"""
import os, logging, json, traceback, time
from typing import List, Generator, Callable
from pathlib import Path
from functools import wraps
from dataclasses import dataclass
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
from threading import Thread

from tqdm import tqdm


class BuildCache:
    lastmod: dict[str, float]  # [abspath, lastmod]

    def __init__(self, cache_json: str = "cache.json"):
        self.cache_json = cache_json
        self.lastmod = {}
        if os.path.exists(cache_json):
            with open(cache_json, "r") as f:
                self.lastmod = json.load(f)

    def check(self, path: Path) -> bool:
        path = os.path.abspath(path)
        res = os.path.exists(path) and os.path.getmtime(path) == self.lastmod.get(
            str(path), 0
        )
        return res

    def update(self, path: Path):
        path = os.path.abspath(path)
        self.lastmod[str(path)] = os.path.getmtime(path)

    def save(self):
        with open(self.cache_json, "w") as f:
            json.dump(self.lastmod, f)


@dataclass
class BuildPrologue:
    """Describes the inputs, outputs and priority for a compilation pass for building the dependency graph.

    - A pass MUST yield a Prologue for it to be valid, or it's culled.
    - A pass MUST contain produce output (outputs not empty), or it's culled.
    - Larger `priority` values will be scheduled first, whilst maintaining dependency order.
    - A pass WITHOUT input dependencies will be scheduled last regardless of priority, and will ALWAYS be executed last.
    """

    name: str
    inputs: List[Path]
    outputs: List[Path]
    priority: int = 1
    # ---
    pid: int = None
    func: str = None

    def has_modified_inputs(self, cache: BuildCache) -> bool:
        return not all(cache.check(input) for input in self.inputs)

    def has_complete_outputs(self, cache: BuildCache) -> bool:
        return all(cache.check(output) for output in self.outputs)

    def need_update(self, cache: BuildCache) -> bool:
        if not self.inputs:
            # No inputs, always need update
            return True
        return self.has_modified_inputs(cache) or not self.has_complete_outputs(cache)

    def mark_updated(self, cache: BuildCache):
        for input in self.inputs:
            cache.update(input)
        for output in self.outputs:
            cache.update(output)        

    def __repr__(self):
        basenames = lambda p: ",".join([os.path.basename(str(s)) for s in p])
        return f"{self.name}(inputs={basenames(self.inputs)}, outputs={basenames(self.outputs)}, priority={self.priority})"


@dataclass
class BuildLog:
    message: str
    # ---
    pid: int = None
    func: str = None


@dataclass
class BuildError:
    exception: Exception
    # ---
    traceback: str = None
    pid: int = 0
    func: str = None


BuildTask = Generator[BuildPrologue | BuildLog | BuildError, None, None]
BuildEvent = BuildPrologue | BuildLog | BuildError


class BuildGraph:
    tasks: List[BuildTask]
    producers: dict[str, int]  # [outname, index]
    prolouges: dict[int, BuildPrologue]  # [index, CompilePrologue]
    phases: List[list]  # [[weight, [index,...], ...] sorted by weight descending

    @staticmethod
    def Task(generator):
        @wraps(generator)
        def wrapper(queue, *args, **kwargs):
            if not queue:
                return generator(*args, **kwargs)
            try:
                for event in generator(*args, **kwargs):
                    event.pid = os.getpid()
                    event.func = generator.__name__
                    queue.put(event)
            except Exception as e:
                queue.put(
                    BuildError(
                        e,
                        traceback=traceback.format_exc(),
                        pid=os.getpid(),
                        func=generator.__name__,
                    )
                )
                raise e

        return wrapper

    def to_graphviz(self, dst: Path, renamer=None):
        with open(dst, "w", encoding="utf-8") as f:
            f.write("digraph G {\n")
            for u in self.graph:
                for v, w in self.graph[u]:
                    if renamer:
                        u = renamer(u)
                        v = renamer(v)
                    f.write(f'    "{v}" -> "{u}"\n')
            f.write("}\n")

    def __init__(self):
        self.tasks = []
        self.logger = logging.getLogger("BuildGraph")

    def submit(self, task: Callable, *args, **kwargs):
        """Submit a new task to the build graph.

        Args:
            task (Callable): The task to be submitted.
        
        Example:
        ```python
        ctx = BuildGraph()
        @BuildGraph.Task # Required
        def compile_usm(src: Path, dst: Path):
            yield BuildPrologue("USM", inputs=[src], outputs=[dst], priority=1)
            yield BuildLog(f"Building USM {src} -> {dst}")
            transcode_usm(
                str(dst),
                str(src),
            )
        
        ctx.submit(compile_usm, mv_m1v_clean, mv_usm)
        ```"""
        self.tasks.append((task, args, kwargs))

    def build(self, artifacts: List[Path] = [], collect_all: bool = False):
        """Build the build graph.

        Once built, the graph can be executed (calling `execute(...)`, possibly multiple times) to process the build tasks.
        Args:
            artifacts (List[Path], optional): A list of artifact paths to include in the build. Defaults to [].
            collect_all (bool, optional): Whether to collect all artifacts, including those not explicitly listed. Defaults to False.

        Raises:
            RecursionError: If a cycle is detected in the build graph.
        """
        self.graph = defaultdict(set)
        self.producers = dict()
        self.prolouges = dict()
        for index, (wrapped, args, kwargs) in enumerate(self.tasks):
            for event in wrapped(None, *args, **kwargs):
                match event:
                    case BuildPrologue(name, inputs, outputs, priority):
                        inputs = [os.path.abspath(str(i)) for i in inputs]
                        outputs = [os.path.abspath(str(o)) for o in outputs]
                        for out in outputs:
                            if out in self.producers:
                                # self.logger.warning(f"{out} is already produced by {self.prolouges[self.producers[out]]} but {event} tries to do it again. The latter will be dropped.")
                                continue
                            self.producers[out] = index
                            self.prolouges[index] = event
                            self.graph[out].update(
                                zip(inputs, [priority] * len(inputs))
                            )
                        break
                    case BuildLog(message):
                        self.logger.info(f"[Build] {wrapped.__name__}: {message}")
        artifacts = set([os.path.abspath(str(a)) for a in artifacts])
        if collect_all:
            artifacts = set(artifacts) | set(self.graph.keys())
        # Topsort and cull
        vis = defaultdict(int)
        deps = defaultdict(int)
        topo = list()

        def dfs(u):
            vis[u] = 1
            for v, w in self.graph[u]:
                if vis[v] == 1:
                    raise RecursionError(f"Cycle detected in graph: {u} -> {v}")
                if vis[v] == 0:
                    dfs(v)
            vis[u] = 2
            topo.append(u)

        for artifact in artifacts:
            if not artifact in self.graph:
                self.logger.error(f"{artifact} is not produced by the current graph")
            if artifact not in vis:
                dfs(artifact)
        for u in reversed(topo):
            for v, w in self.graph[u]:
                # Modified Longest path
                # Starting nodes of each path will receive weights of w * len(path)
                deps[u] = max(w, deps[u])
                deps[v] = max(deps[u] + w, deps[v])
        self.phases = defaultdict(set)
        for u in topo:
            if u in self.producers:
                self.phases[deps[u]].add(self.producers[u])
            # Local file otherwise
        self.phases = sorted(self.phases.items())[::-1]

    def _execute_handle_event(self, evt: BuildEvent):
        match evt:
            case BuildPrologue(name, inputs, outputs, priority, pid, func):
                logger = logging.getLogger(func or self.logger.name)
                logger.debug(f"@{pid:5d} Building {name}")
            case BuildError(exception, tb, pid, func):
                logger = logging.getLogger(func or self.logger.name)
                logger.error(f"@{pid:5d} Uncaught error: {exception}")
                logger.error(f"{tb}")
            case BuildLog(message, pid, func):
                logger = logging.getLogger(func or self.logger.name)
                if pid:
                    logger.info(f"@{pid:5d} {message}")
                else:
                    logger.info(f"{message}")

    def _execute_setup_mp(self, num_workers: int = None):
        self.logger.info("Spawning workers")
        self.mp_queue = Manager().Queue()
        self.mp_pool = ProcessPoolExecutor(max_workers=num_workers)

        def mp_queue_listener():
            while True:
                event = self.mp_queue.get()
                if event is None:
                    break
                self._execute_handle_event(event)

        self.mp_listener = Thread(target=mp_queue_listener)
        self.mp_listener.start()
        self.logger.info(f"Using {self.mp_pool._max_workers} worker processes")

    exec_errors, exec_success = 0, 0
    failfast = False

    def _execute_phase_mp(self, phase: list, cache: BuildCache, desc="Phase MP"):
        futures = []
        for task in phase:
            wrapped, args, kwargs = self.tasks[task]
            future = self.mp_pool.submit(wrapped, self.mp_queue, *args, **kwargs)
            future.task_id = task
            futures.append(future)
        for future in tqdm(as_completed(futures), desc=desc, total=len(futures)):
            try:
                future.result()
                self.prolouges[future.task_id].mark_updated(cache)
                self.exec_success += 1
            except:
                self.exec_errors += 1
                if self.failfast:
                    raise RuntimeError("Failfast enabled, stopping execution")

    def _execute_phase_sp(self, phase: list, cache: BuildCache, desc="Phase SP"):
        for task in tqdm(phase, desc=desc):
            wrapped, args, kwargs = self.tasks[task]
            try:
                for event in wrapped(None, *args, **kwargs):
                    self._execute_handle_event(event)
                self.prolouges[task].mark_updated(cache)
                self.exec_success += 1
            except:
                self.exec_errors += 1
                if self.failfast:
                    raise RuntimeError("Failfast enabled, stopping execution")

    def _execute_cleanup_mp(self):
        self.mp_queue.put(None)
        self.mp_listener.join()

    def execute(self, cache: BuildCache, mp: int = 1, failfast: bool = False):
        """Execute the build process.

        Args:
            cache (BuildCache): The build cache.
            mp (int, optional): The number of worker processes to use. Defaults to 1.
            failfast (bool, optional): Whether to stop on the first error. Defaults to False.

        Note:
            If `mp` is greater than 1, multiprocessing will be used, otherwise everything
            will run on the calling thread.
        """
        assert self.phases, "Graph not built, call build() first"
        self.failfast = failfast
        self.exec_errors = 0
        if mp > 1:
            self._execute_setup_mp(mp)
        t_start = time.time()
        exec_culled = 0
        for i, (j, phases) in enumerate(self.phases, start=1):
            exec_phases = []
            # Cull unmodified inputs
            for phase in phases:
                prologue = self.prolouges[phase]
                if not prologue.need_update(cache):
                    self.logger.debug(f"{prologue} checked out")
                else:
                    exec_phases.append(phase)
            exec_culled += len(phases) - len(exec_phases)
            if not exec_phases:
                continue
            if mp > 1:
                self._execute_phase_mp(
                    exec_phases, cache, f"Phase MP [{i:2d}/{len(self.phases):2d}]"
                )
            else:
                self._execute_phase_sp(
                    exec_phases, cache, f"Phase SP [{i:2d}/{len(self.phases):2d}]"
                )
            cache.save()
        t_end = time.time()
        self.logger.info(
            f"Build finished in {t_end - t_start:.2f}s, {self.exec_success} succeeded, {self.exec_errors} failed, {exec_culled} up-to-date"
        )
        if mp > 1:
            self._execute_cleanup_mp()
