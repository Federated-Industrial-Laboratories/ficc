# SPDX-License-Identifier: Apache-2.0
"""Translate engine semantics into immutable executor jobs, never process ownership."""
from importlib.metadata import entry_points
from pathlib import PurePosixPath

from ..errors import Failure
from ..execution.spec import Endpoint, Job, Payload


class Adapter:
    def __init__(self, name):
        self.name = name

    def job(self, spec, model, placement, inputs):
        manifest = model["manifest"]
        if manifest["format"] != ("safetensors" if self.name == "vllm" else "gguf"):
            raise Failure("model_format", "The selected engine does not support this model format.", 409)
        gpu = placement.limits.gpu_devices
        environment = {"CUDA_VISIBLE_DEVICES": ",".join(gpu), "HOME": "/work", "TMPDIR": "/work", "XDG_CACHE_HOME": "/work/.cache"}
        path = "/inputs/" + manifest["entrypoint"]
        if self.name == "llama_cpp":
            environment["LD_LIBRARY_PATH"] = str(PurePosixPath(spec.executable).parent) + ":/usr/local/cuda/lib64:/usr/local/nvidia/lib64:/usr/lib/x86_64-linux-gnu:/usr/lib64:/usr/lib"
            argv = [spec.executable, "--model", path, "--host", "/work/inference.sock", "--alias", spec.alias,
                    "--ctx-size", str(spec.context * spec.concurrency), "--parallel", str(spec.concurrency), "--n-gpu-layers", str(spec.gpu_layers)]
            if gpu and spec.gpu_layers:
                argv += ["--device", ",".join("CUDA" + str(index) for index in range(len(gpu)))]
            if len(gpu) > 1:
                argv += ["--split-mode", "layer", "--tensor-split", ",".join(str(x) for x in (spec.tensor_split or [1] * len(gpu)))]
            if "embeddings" in manifest["capabilities"]:
                argv += ["--embedding"]
            paths = ["/health", "/v1/models", "/v1/chat/completions", "/v1/embeddings"]
        elif self.name == "ollama":
            argv = ["/ficc/socket-proxy", "/work/inference.sock", "11434", "--", spec.executable, "serve"]
            environment.update(OLLAMA_HOST="127.0.0.1:11434", OLLAMA_MODELS="/work/ollama", OLLAMA_NO_CLOUD="1",
                               OLLAMA_NUM_PARALLEL=str(spec.concurrency), OLLAMA_CONTEXT_LENGTH=str(spec.context), OLLAMA_KEEP_ALIVE="-1")
            paths = ["/api/version", "/api/blobs", "/api/create", "/api/show", "/api/ps", "/api/chat", "/api/embed", "/v1/models", "/v1/chat/completions", "/v1/embeddings"]
        elif self.name == "vllm":
            argv = ["/ficc/socket-proxy", "/work/inference.sock", "8000", "--", spec.executable, "serve", "/inputs",
                    "--host", "127.0.0.1", "--port", "8000", "--served-model-name", spec.alias,
                    "--max-model-len", str(spec.context), "--max-num-seqs", str(spec.concurrency),
                    "--" + spec.parallelism + "-parallel-size", str(max(1, len(gpu)))]
            environment.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HOME="/work/huggingface",
                               VLLM_CACHE_ROOT="/work/vllm-cache", TORCHINDUCTOR_CACHE_DIR="/work/torch-cache",
                               LD_LIBRARY_PATH="/usr/local/nvidia/lib64:/usr/local/nvidia/lib:/usr/local/cuda/lib64:/usr/lib/x86_64-linux-gnu:/usr/lib64:/usr/lib")
            paths = ["/health", "/v1/models", "/v1/chat/completions", "/v1/embeddings"]
        else:
            raise Failure("engine_unavailable", "The selected inference adapter is not installed.", 409)
        if sum(item.bytes for item in inputs) * (2 if self.name == "ollama" else 1) + 64 * 1024 * 1024 > placement.limits.storage_bytes:
            raise Failure("model_capacity", "Reserve model inputs plus runtime and scratch storage before deployment.", 409)
        return Job(name="Inference " + spec.alias, runtime=spec.runtime, payload=Payload(argv=argv, environment=environment),
                   limits=placement.limits, inputs=inputs, outputs=[], sensitive=True,
                   endpoint=Endpoint(socket="inference.sock", paths=paths, concurrency=spec.concurrency + 2))


class Providers:
    def __init__(self):
        self.adapters = {name: Adapter(name) for name in ("llama_cpp", "ollama", "vllm")}
        for entry in entry_points(group="ficc.inference"):
            if entry.name in self.adapters:
                raise ValueError("An inference adapter cannot shadow a shipped adapter.")
            adapter = entry.load()()
            if getattr(adapter, "API_VERSION", None) != 1 or not callable(getattr(adapter, "job", None)):
                raise ValueError("The inference adapter must implement API version 1 and job().")
            self.adapters[entry.name] = adapter

    def get(self, name):
        if name not in self.adapters:
            raise Failure("engine_unavailable", "Install the selected inference adapter before deploying.", 409)
        return self.adapters[name]
