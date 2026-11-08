"""Offline guard regressions. No application imports, Docker, or evidence writes."""
import ast
import copy
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import typing
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("benchmark_safety", ROOT / "benchmark_safety.py")
safety = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safety)

# Explicit inventory: each public mutating entrypoint must refuse before any work.
HOST_ENTRIES = {
    "eval_common.py": ["reset_ledger_and_restart_services"],
    "run_tamper_detection.py": ["run_benchmark"],
    "run_verification_scaling.py": ["run_scaling_benchmark"],
    "test_exp_a_multi_tamper.py": ["run_experiment_a"],
    **{f"run_exp_{c}_suite.py": [f"run_exp_{c}_suite"] for c in "bcdef"},
    "run_extended_e1_tamper.py": ["run_e1_suite"],
    "run_extended_e2_failure_modes.py": ["run_e2_suite", "execute_chat_turns_in_container"],
    "run_extended_e3_concurrency.py": ["run_e3_suite"],
    "run_extended_e4_lineage.py": ["run_e4_suite"],
    "run_malformed_reconfirm.py": ["run_malformed_reconfirm"],
    "run_q1_true_midchain.py": ["run_true_midchain_evaluation"],
    "run_v2_tamper.py": ["run_v2_tamper_suite"],
    "run_v2_failure_modes.py": ["run_v2_failure_modes_suite", "execute_chat_turns_in_container"],
    "run_v2_concurrency.py": ["run_v2_concurrency_suite"],
    "run_v2_latency.py": ["run_v2_latency_suite"],
    "run_tail_rewrite_class.py": ["run_tail_rewrite_test"],
    "run_anchor_cost_ab.py": ["main", "switch_anchor_every", "reset_db_and_anchors", "run_trial"],
    "test_exp_b2_next_counter.py": ["run_experiment_b2"],
    "run_rq1_30seed.py": ["main", "run_seed", "reset_ledger_and_restart", "aggregate_and_write_reports"],
    "run_live_ingest_tamper_v2.py": ["run_live_tamper_suite"],
    "smoke_test.py": ["smoke_test"],
}
NATIVE_ENTRIES = {
    "container_variant_bench.py": ["main", "run_variant"],
    "measure_ingest_variants.py": ["main", "run_variant_trial"],
    "run_variant_throughput.py": ["main", "run_test", "build_app"],
    "consolidate_extra_results.py": ["main"],
    "generate_all_reports.py": ["generate_reports"],
    "run_audit_overhead.py": ["main", "run_trials"],
    "test_exp_b_token_forgery.py": ["run_experiment_b"],
    "test_exp_c_concurrency.py": ["run_experiment_c", "worker_task"],
    "test_exp_d_queue_pressure.py": ["run_experiment_d"],
    "test_exp_f_malformed.py": ["run_suite"],
    "run_naive_baseline.py": ["run_condition_b", "__init__"],
    "naive_logging_stub.py": ["__init__"],
    "run_isolation_test.py": ["test_sqlite_file_and_host", "test_reconstruction_http", "test_audit_ingest_data_leakage"],
}
LIVE = ["run_live_ingest_tamper_v2.py"]


def tree_for(filename):
    return ast.parse((ROOT / filename).read_text(encoding="utf-8"), filename)


def isolated_function(filename, name):
    """Compile only the requested function, never execute experiment module imports."""
    node = next(n for n in ast.walk(tree_for(filename)) if isinstance(n, ast.FunctionDef) and n.name == name)
    namespace = dict(vars(typing))
    namespace.update(
        os=os, require_destructive=safety.require_destructive,
        require_token=safety.require_token, validate_target=safety.validate_target,
        guarded_python=safety.guarded_python,
        reset_ledger_and_restart_services=Mock(), open=Mock(side_effect=AssertionError("output opened")),
    )
    exec(compile(ast.Module(body=[copy.deepcopy(node)], type_ignores=[]), filename, "exec"), namespace)
    required = len(node.args.args) - len(node.args.defaults)
    return namespace[name], namespace, [None] * required


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.process = patch.object(safety.subprocess, "run", side_effect=AssertionError("unexpected subprocess"))
        self.process.start()
        self.addCleanup(self.process.stop)

    def test_opt_in_must_be_exact(self):
        for value in [None, "", "0", "true", "yes", " 1", "1 "]:
            with self.subTest(value=value):
                if value is None:
                    os.environ.pop("AEGIS_ALLOW_DESTRUCTIVE", None)
                else:
                    os.environ["AEGIS_ALLOW_DESTRUCTIVE"] = value
                with self.assertRaisesRegex(SystemExit, "AEGIS_ALLOW_DESTRUCTIVE=1"):
                    safety.require_destructive("http://localhost", docker=True)

    def test_allowed_actual_hosts(self):
        os.environ["AEGIS_ALLOW_DESTRUCTIVE"] = "1"
        for host in sorted(safety.ALLOWED_HOSTS):
            for scheme in ["http", "https"]:
                safety.require_destructive(f"{scheme}://{host}:8001/ingest")

    def test_bad_actual_target_despite_opt_in(self):
        os.environ["AEGIS_ALLOW_DESTRUCTIVE"] = "1"
        for target in [
            None, "", "localhost", "//localhost/a", "file:///localhost/a",
            "http://remote.invalid/ingest", "http://localhost.remote.invalid",
            "http://127.0.0.2/ingest", "http://[::1]", "http://localhost:",
            "http://localhost:99999", "http://localhost:0", "http://localhost:bad",
            "http://localhost:80:81", "http://localhost/a#fragment",
            "http://user:credential@localhost/ingest", "http://localhost@remote.invalid",
            "http://localhost\\@remote.invalid", "http://local%68ost", "http://[localhost]",
            " http://localhost", "http://local\nhost", "http:///localhost",
        ]:
            with self.subTest(target=target):
                with self.assertRaises(SystemExit) as caught:
                    safety.require_destructive("http://127.0.0.1:8002", target)
                self.assertNotIn("user:credential", str(caught.exception))
                self.assertNotIn("remote.invalid", str(caught.exception))

    def test_every_entry_refuses_without_or_with_wrong_opt_in(self):
        os.environ["AUDIT_WRITE_TOKEN"] = "synthetic-test-only"
        for filename, names in {**HOST_ENTRIES, **NATIVE_ENTRIES}.items():
            for name in names:
                for opt_in in ["", "true"]:
                    with self.subTest(filename=filename, name=name, opt_in=opt_in):
                        os.environ["AEGIS_ALLOW_DESTRUCTIVE"] = opt_in
                        fn, namespace, args = isolated_function(filename, name)
                        with self.assertRaisesRegex(SystemExit, "AEGIS_ALLOW_DESTRUCTIVE"):
                            fn(*args)
                        namespace["open"].assert_not_called()
                        if name != "reset_ledger_and_restart_services":
                            namespace["reset_ledger_and_restart_services"].assert_not_called()

    def test_missing_host_token_precedes_reset_and_outputs(self):
        os.environ["AEGIS_ALLOW_DESTRUCTIVE"] = "1"
        for filename in LIVE:
            for value in [None, "", "   "]:
                with self.subTest(filename=filename, value=value):
                    if value is None:
                        os.environ.pop("AUDIT_WRITE_TOKEN", None)
                    else:
                        os.environ["AUDIT_WRITE_TOKEN"] = value
                    fn, namespace, _ = isolated_function(filename, "run_live_tamper_suite")
                    with patch.object(os, "makedirs") as mkdir:
                        with self.assertRaisesRegex(SystemExit, "AUDIT_WRITE_TOKEN"):
                            fn()
                    mkdir.assert_not_called()
                    namespace["open"].assert_not_called()
                    namespace["reset_ledger_and_restart_services"].assert_not_called()

    def test_remote_docker_and_context_fail_closed(self):
        os.environ["AEGIS_ALLOW_DESTRUCTIVE"] = "1"
        for endpoint in ["ssh://server", "tcp://remote:2375", "tcp://localhost:2375", "npipe:////server/pipe/docker_engine"]:
            os.environ["DOCKER_HOST"] = endpoint
            with self.assertRaisesRegex(SystemExit, "DOCKER_HOST"):
                safety.require_destructive("http://localhost", docker=True)
        os.environ.pop("DOCKER_HOST")
        for data in ["not json", "[]", '[{"Endpoints":{"docker":{"Host":"ssh://server"}}}]']:
            with patch.object(safety.subprocess, "run", return_value=SimpleNamespace(stdout=data)):
                with self.assertRaisesRegex(SystemExit, "Docker context"):
                    safety.require_destructive(docker=True)

    def test_local_docker_and_context_precedence(self):
        os.environ["AEGIS_ALLOW_DESTRUCTIVE"] = "1"
        for endpoint in ["unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine"]:
            os.environ["DOCKER_HOST"] = endpoint
            safety.require_destructive(docker=True)
        os.environ["DOCKER_CONTEXT"] = "selected-context"
        remote = SimpleNamespace(stdout='[{"Endpoints":{"docker":{"Host":"ssh://server"}}}]')
        with patch.object(safety.subprocess, "run", return_value=remote) as run:
            with self.assertRaises(SystemExit):
                safety.require_destructive(docker=True)
            self.assertEqual(run.call_args.args[0], ["docker", "context", "inspect", "selected-context"])
        local = SimpleNamespace(stdout='[{"Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}}}]')
        with patch.object(safety.subprocess, "run", return_value=local):
            safety.require_destructive(docker=True)

    def test_container_preflight_precedes_live_reset_and_output(self):
        os.environ.update(AEGIS_ALLOW_DESTRUCTIVE="1", AUDIT_WRITE_TOKEN="synthetic-test-only", DOCKER_HOST="unix:///var/run/docker.sock")
        for filename in LIVE:
            fn, namespace, _ = isolated_function(filename, "run_live_tamper_suite")
            with patch.object(safety.subprocess, "run", return_value=SimpleNamespace(returncode=1)) as run:
                with self.assertRaisesRegex(SystemExit, "agent preflight failed"):
                    fn()
                script = run.call_args_list[0].kwargs["input"]
                self.assertIn("require_token()", script)
                self.assertIn("AUDIT_SINK_URL", script)
            namespace["open"].assert_not_called()
            namespace["reset_ledger_and_restart_services"].assert_not_called()

    def test_transport_is_self_contained_and_never_auto_enables(self):
        os.environ.update(AEGIS_ALLOW_DESTRUCTIVE="1", DOCKER_HOST="unix:///var/run/docker.sock")
        script = safety.guarded_python("ran = True\n")
        with patch.dict(sys.modules):
            namespace = {"__name__": "__main__"}
            exec(script, namespace)
            self.assertTrue(namespace["ran"])
            os.environ.pop("AEGIS_ALLOW_DESTRUCTIVE")
            namespace = {"__name__": "__main__"}
            with self.assertRaisesRegex(SystemExit, "AEGIS_ALLOW_DESTRUCTIVE"):
                exec(script, namespace)
            self.assertNotIn("ran", namespace)

    def test_embedded_live_ingest_missing_token(self):
        os.environ.update(AEGIS_ALLOW_DESTRUCTIVE="1", DOCKER_HOST="unix:///var/run/docker.sock")
        for filename, varname in [(LIVE[0], "ingest_runner_code"), ("run_rq1_30seed.py", "ingest_script")]:
            node = next(n for n in ast.walk(tree_for(filename)) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == varname for t in n.targets))
            # Only interpolate the session-list literal; never call the experiment.
            expr = copy.deepcopy(node.value)
            for i, value in enumerate(expr.values):
                if isinstance(value, ast.FormattedValue):
                    expr.values[i] = ast.Constant("[]")
            code = eval(compile(ast.fix_missing_locations(ast.Expression(expr)), filename, "eval"))
            script = safety.guarded_python(code)
            with patch.dict(sys.modules, {"httpx": SimpleNamespace()}):
                with self.assertRaisesRegex(SystemExit, "AUDIT_WRITE_TOKEN"):
                    exec(script, {"__name__": "__main__"})

    def test_container_preflight_checks_its_effective_override(self):
        os.environ.update(AEGIS_ALLOW_DESTRUCTIVE="1", AUDIT_WRITE_TOKEN="synthetic-test-only", DOCKER_HOST="unix:///var/run/docker.sock")
        with patch.object(safety.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            safety.require_destructive(docker=True, agent=True)
            agent_script = run.call_args_list[0].kwargs["input"]
            anchor_script = run.call_args_list[1].kwargs["input"]
        for target in ["http://remote.invalid/ingest", "http://user:credential@localhost/ingest", "not-a-url"]:
            os.environ["AUDIT_SINK_URL"] = target
            with patch.dict(sys.modules):
                with self.assertRaisesRegex(SystemExit, "target URL"):
                    exec(agent_script, {"__name__": "__main__"})
        for target in ["http://remote.invalid/anchor", "http://user:credential@localhost/anchor", "not-a-url"]:
            os.environ["ANCHOR_SINK_URL"] = target
            with patch.dict(sys.modules):
                with self.assertRaisesRegex(SystemExit, "target URL"):
                    exec(anchor_script, {"__name__": "__main__"})
        os.environ.pop("ANCHOR_SINK_URL")
        os.environ["ANCHOR_EVERY"] = "10"
        os.environ.pop("ANCHOR_WRITE_TOKEN", None)
        with patch.dict(sys.modules):
            with self.assertRaisesRegex(SystemExit, "ANCHOR_WRITE_TOKEN"):
                exec(anchor_script, {"__name__": "__main__"})

    def test_factory_capture_target_is_checked(self):
        os.environ["AEGIS_ALLOW_DESTRUCTIVE"] = "1"
        fn, _, _ = isolated_function("run_audit_overhead.py", "run_trials")
        capture = SimpleNamespace(audit_url="http://remote.invalid/ingest")
        with self.assertRaisesRegex(SystemExit, "target URL"):
            fn(lambda: (object(), capture), "TEST")

    def test_transported_reset_refuses_before_sqlite(self):
        os.environ.update(AEGIS_ALLOW_DESTRUCTIVE="1", DOCKER_HOST="unix:///var/run/docker.sock")
        tree = tree_for("eval_common.py")
        reset = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "reset_ledger_and_restart_services")
        sql = next(n.value.value for n in reset.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "sql" for t in n.targets))
        script = safety.guarded_python(sql)
        os.environ.pop("AEGIS_ALLOW_DESTRUCTIVE")
        connect = Mock(side_effect=AssertionError("SQLite accessed"))
        with patch.dict(sys.modules, {"sqlite3": SimpleNamespace(connect=connect)}):
            with self.assertRaisesRegex(SystemExit, "AEGIS_ALLOW_DESTRUCTIVE"):
                exec(script, {"__name__": "__main__"})
        connect.assert_not_called()

    def test_actual_worker_url_is_checked(self):
        os.environ["AEGIS_ALLOW_DESTRUCTIVE"] = "1"
        fn, _, _ = isolated_function("test_exp_c_concurrency.py", "worker_task")
        with self.assertRaisesRegex(SystemExit, "target URL"):
            fn(0, 1, 1, "http://remote.invalid/ingest", "synthetic-test-only")


class CoverageTests(unittest.TestCase):
    def test_all_docker_python_transfers_are_guarded(self):
        count = 0
        for filename in HOST_ENTRIES:
            tree = tree_for(filename)
            if filename == "eval_common.py":
                tree = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "reset_ledger_and_restart_services")
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not node.args or not isinstance(node.args[0], ast.List):
                    continue
                values = [n.value if isinstance(n, ast.Constant) else None for n in node.args[0].elts]
                if values[:2] != ["docker", "exec"] or "python" not in values:
                    continue
                count += 1
                self.assertEqual(values[2:4], ["-e", "AEGIS_ALLOW_DESTRUCTIVE"], filename)
                if "-c" in values:
                    payload = node.args[0].elts[values.index("-c") + 1]
                else:
                    payload = next(kw.value for kw in node.keywords if kw.arg == "input")
                self.assertIsInstance(payload, ast.Call, filename)
                self.assertEqual(payload.func.id, "guarded_python", filename)
        self.assertGreater(count, 80)

    def test_every_excluded_output_directory_created_before_open(self):
        dirs = ["results/raw", "results/raw_v2", "results/logs", "results/logs_v2", "evaluation_results/raw_logs"]
        writers = 0
        for path in ROOT.glob("*.py"):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source)
            for directory in dirs:
                # Literal paths and paths assigned to output variables are both covered.
                paths = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith(directory + "/") and "\n" not in n.value]
                if not paths or path.name in {"generate_all_reports.py", "benchmark_safety.py"}:
                    continue
                if path.name == "run_rq1_30seed.py":
                    self.assertIn('os.makedirs(output_dir, exist_ok=True)', source)
                    continue
                mkdir = f'os.makedirs("{directory}", exist_ok=True)'
                self.assertIn(mkdir, source, path.name)
                mkdir_line = source[:source.index(mkdir)].count("\n") + 1
                self.assertLess(mkdir_line, min(n.lineno for n in paths), path.name)
                writers += 1
        self.assertGreater(writers, 20)

    def test_output_mkdir_calls_are_idempotent_in_scratch_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            created = set()
            def mkdir(path, exist_ok=False):
                # Redirect only output directory creation, never run an experiment.
                self.assertTrue(exist_ok)
                self.assertFalse(Path(path).is_absolute())
                (base / path).mkdir(parents=True, exist_ok=exist_ok)
                created.add(path)
            namespace = {"os": SimpleNamespace(makedirs=mkdir), "output_dir": "results/raw_v2/rq1_30seed"}
            for path in ROOT.glob("*.py"):
                for node in ast.walk(tree_for(path.name)):
                    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                        continue
                    if not isinstance(node.func.value, ast.Name) or node.func.value.id != "os" or node.func.attr != "makedirs":
                        continue
                    if not node.args or not isinstance(node.args[0], (ast.Constant, ast.Name)):
                        continue
                    expr = ast.Expression(copy.deepcopy(node))
                    code = compile(expr, path.name, "eval")
                    eval(code, namespace)
                    eval(code, namespace)
            for directory in ["results/raw", "results/raw_v2", "results/logs", "results/logs_v2", "evaluation_results/raw_logs"]:
                self.assertIn(directory, created)
                self.assertTrue((base / directory).is_dir())

    def test_syntax_and_inventory(self):
        for path in ROOT.glob("*.py"):
            ast.parse(path.read_text(encoding="utf-8"), str(path))
        known_non_live = {"benchmark_safety.py", "check_db.py", "run_v2_tamper_live_ingest.py"}
        actual = {p.name for p in ROOT.glob("*.py")}
        self.assertEqual(actual - known_non_live, set(HOST_ENTRIES) | set(NATIVE_ENTRIES))


if __name__ == "__main__":
    unittest.main()
