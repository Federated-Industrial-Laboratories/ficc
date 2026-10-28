# Inference runtime images

Use an approved upstream image directly when its image-import working set fits
the executor slot. OCI import needs both compressed staging and extracted layers;
the download size alone is not its disk requirement.

For a smaller dense CUDA llama.cpp runtime, this recipe retains the upstream
server, its license files, cuBLAS, CUDA runtime and JIT libraries. It removes the
optional CUDA FFT, random, solver, sparse, image-processing and JPEG libraries.
The build refuses an upstream link dependency on those libraries. Use the
upstream image for an extension that requires them.

Select an immutable, reviewed upstream image and build without a network:

```sh
podman build --network=none --pull=never --squash-all \
  --build-arg LLAMA_IMAGE=APPROVED_LOCAL_IMAGE \
  --file llama-cpp.Containerfile --tag localhost/ficc-llama-cuda .
podman save --format oci-archive --output llama-cuda.oci.tar \
  localhost/ficc-llama-cuda
podman load --input llama-cuda.oci.tar
podman image inspect localhost/ficc-llama-cuda --format '{{.Id}}'
sha256sum llama-cuda.oci.tar
```

Load the reviewed upstream image into the build store before this command.
`--squash-all` is required: deleting files in another layer alone does not reduce
the imported base layers. Register the exported image ID and archive SHA256 in
the normal executor image configuration, then qualify its API and GPU operation.
Use the config digest from the exported OCI manifest, or inspect the image after
loading that archive into the build store. Export can normalize Docker image
configuration and change this digest while preserving its layers and runtime
settings. The source registry manifest digest and the archive's reference-name
annotation are not the loaded image ID. The executor requires an exact match.
FICC does not select an image version or fetch runtime code inside a workload.
