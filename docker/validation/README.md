# Docker-only validation image

Build this image from an audited Ubuntu 22.04 environment, then configure OHScanner with its immutable local image ID (sha256:<64 hex>), not a mutable tag. The worker checks the configured ID/digest against Docker local image metadata and never pulls an image during validation.

Build: docker build --pull -t ohscanner-validation:local docker/validation
Inspect the immutable image ID with docker image inspect ohscanner-validation:local --format {{.Id}}.

Set OHSCANNER_VALIDATION_IMAGE=sha256:<image-id> in the workbench service environment and restart the service. The image is not part of source sync or a web-upload option. Rebuilds create a new image ID and need an explicit configuration change.

At runtime the worker mounts the application and pinned Git sources read-only; only the operation scratch/result directory is writable. It sets --network none, drops all Linux capabilities, enables no-new-privileges, uses a read-only container root, and caps memory, CPU, process count, and runtime. The Docker socket is never mounted into the container. If Docker, the configured image, or pinned source objects are unavailable, the operation is blocked; it does not run the harness on the host.

Image contents and compiler version are recorded with each result. The base apt repository is not a reproducible package lock; the resulting immutable image ID pins the actual bytes used. For strict rebuild reproducibility, archive the image and its Docker build context as a separate release artifact.
