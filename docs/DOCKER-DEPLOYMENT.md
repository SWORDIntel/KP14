# KP14 KEYPLUG Analyzer - Docker Deployment Guide

## Overview

This Docker deployment provides a production-ready, containerized environment for the KP14 KEYPLUG Analyzer with:

- **Hardware Acceleration**: Intel OpenVINO support for GPU/NPU inference
- **Security Hardening**: Non-root execution, minimal attack surface
- **Reproducibility**: Consistent environment across systems
- **One-Command Startup**: Simplified deployment and usage
- **Resource Management**: CPU and memory limits for safe operation

## Quick Start

### 1. Build the Image

```bash
./docker-build.sh
```

This creates the `kp14-keyplug-analyzer:latest` Docker image.

### 2. Prepare Your Files

```bash
# Place files to analyze in the input directory
mkdir -p input
cp /path/to/suspicious-file.jpg input/

# Output will be saved here
mkdir -p output
```

### 3. Run Analysis

```bash
# Analyze a file
./docker-run.sh suspicious-file.jpg

# Or use docker-compose
docker-compose run kp14-analyzer /home/kp14/input/suspicious-file.jpg
```

## Architecture

### Multi-Stage Build

The Dockerfile uses a multi-stage build for optimal image size:

1. **Builder Stage**: Compiles dependencies with development tools
2. **Runtime Stage**: Minimal Debian Bookworm with only runtime requirements

### Components

- **Base OS**: Debian Bookworm Slim
- **Python**: 3.11+ with virtual environment
- **OpenVINO**: 2025.0.0+ (latest available)
- **Dependencies**: OpenCV, NumPy, Pillow, pefile, capstone
- **User**: Non-root `kp14` user (UID 1000)

## File Structure

```
kp14/
├── Dockerfile              # Multi-stage Docker build
├── docker-compose.yml      # Orchestration configuration
├── .dockerignore          # Build context exclusions
├── docker-build.sh        # Build helper script
├── docker-run.sh          # Run helper script
├── docker/
│   └── entrypoint.sh      # Container entrypoint
├── input/                 # Mount: Input files (read-only)
├── output/                # Mount: Analysis results (read-write)
└── models/                # Mount: ML models (read-only)
```

## Usage

### Method 1: Helper Scripts (Recommended)

#### Build

```bash
./docker-build.sh [TAG]

# Examples:
./docker-build.sh              # Build with 'latest' tag
./docker-build.sh v1.0         # Build with 'v1.0' tag
```

#### Run

```bash
./docker-run.sh [OPTIONS] <input-file>

# Options:
#   -i, --input-dir DIR     Input directory
#   -o, --output-dir DIR    Output directory
#   -m, --models-dir DIR    Models directory
#   -s, --settings FILE     Settings file
#   --no-gpu                Disable GPU acceleration
#   --keep                  Keep container after exit
#   --shell                 Start interactive shell

# Examples:
./docker-run.sh malware.exe                    # Analyze file
./docker-run.sh -s custom.ini sample.jpg       # Custom settings
./docker-run.sh --shell                        # Interactive shell
./docker-run.sh --test                         # Run self-test
```

### Method 2: Docker Compose

```bash
# Build
docker-compose build

# Run analysis
docker-compose run --rm kp14-analyzer /home/kp14/input/file.bin

# Interactive mode
docker-compose run --rm kp14-analyzer bash

# Background service (if configured)
docker-compose up -d
docker-compose logs -f
docker-compose down
```

### Method 3: Direct Docker Commands

```bash
# Build
docker build -t kp14-keyplug-analyzer:latest .

# Run with GPU acceleration
docker run --rm -it \
  -v $(pwd)/input:/home/kp14/input:ro \
  -v $(pwd)/output:/home/kp14/output:rw \
  --device /dev/dri:/dev/dri \
  kp14-keyplug-analyzer:latest \
  /home/kp14/input/suspicious.jpg

# Run without GPU
docker run --rm -it \
  -v $(pwd)/input:/home/kp14/input:ro \
  -v $(pwd)/output:/home/kp14/output:rw \
  -e OPENVINO_DEVICE=CPU \
  kp14-keyplug-analyzer:latest \
  /home/kp14/input/file.bin
```

## Hardware Acceleration

### Intel GPU/NPU

The container supports Intel integrated graphics (GPU) and Neural Processing Units (NPU) via OpenVINO:

```bash
# Auto-detect best device
docker run --device /dev/dri:/dev/dri \
  -e OPENVINO_DEVICE=AUTO \
  kp14-keyplug-analyzer:latest <file>

# Force GPU
docker run --device /dev/dri:/dev/dri \
  -e OPENVINO_DEVICE=GPU \
  kp14-keyplug-analyzer:latest <file>

# Force NPU (if available)
docker run --device /dev/dri:/dev/dri \
  -e OPENVINO_DEVICE=NPU \
  kp14-keyplug-analyzer:latest <file>
```

### Verify Hardware Access

```bash
# Check available OpenVINO devices
docker run --rm --device /dev/dri:/dev/dri \
  kp14-keyplug-analyzer:latest test

# Check OpenCL devices
docker run --rm --device /dev/dri:/dev/dri \
  kp14-keyplug-analyzer:latest bash -c "clinfo -l"
```

### No GPU Available

If no GPU/NPU is available, the container automatically falls back to CPU-only inference:

```bash
./docker-run.sh --no-gpu file.jpg
```

## Configuration

### Environment Variables

Set in `docker-compose.yml` or pass with `-e`:

```bash
# OpenVINO device selection
OPENVINO_DEVICE=AUTO          # AUTO, CPU, GPU, NPU, MULTI:GPU,CPU

# Logging
KP14_LOG_LEVEL=INFO           # DEBUG, INFO, WARNING, ERROR
KP14_VERBOSE=true             # Enable verbose output

# System
TZ=UTC                        # Timezone
PYTHONUNBUFFERED=1            # Unbuffered Python output
```

### Settings File

Mount a custom `settings.ini`:

```bash
docker run -v $(pwd)/custom-settings.ini:/home/kp14/analyzer/settings.ini:ro \
  kp14-keyplug-analyzer:latest <file>
```

### Resource Limits

Edit `docker-compose.yml` to adjust:

```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'       # Maximum CPU cores
      memory: 8G        # Maximum RAM
    reservations:
      cpus: '1.0'       # Minimum CPU cores
      memory: 2G        # Minimum RAM
```

## Security

### Non-Root Execution

The container runs as user `kp14` (UID 1000) for security:

```bash
docker run --rm kp14-keyplug-analyzer:latest bash -c "whoami && id"
# Output: kp14
#         uid=1000(kp14) gid=1000(kp14) groups=1000(kp14)
```

### Capability Restrictions

Only necessary capabilities are granted:

- `DAC_OVERRIDE`: File analysis operations
- `CHOWN`: Output file permissions

All other capabilities are dropped for minimal attack surface.

### Read-Only Input

Input files are mounted read-only to prevent tampering:

```bash
-v $(pwd)/input:/home/kp14/input:ro  # Read-only
```

### Security Options

```yaml
security_opt:
  - no-new-privileges:true    # Prevent privilege escalation
  - seccomp:unconfined        # Required for some analysis tools
```

## Troubleshooting

### Image Build Fails

```bash
# Clear build cache
docker system prune -a

# Build with no cache
docker build --no-cache -t kp14-keyplug-analyzer:latest .

# Check disk space
df -h
docker system df
```

### OpenVINO Installation Issues

```bash
# Check installed version
docker run --rm kp14-keyplug-analyzer:latest \
  python3 -c "import openvino; print(openvino.__version__)"

# Manually install specific version
# Edit Dockerfile:
RUN pip install openvino==2024.4.0
```

### GPU Not Detected

```bash
# Verify host GPU access
ls -la /dev/dri/

# Check if device is passed through
docker run --rm --device /dev/dri:/dev/dri \
  kp14-keyplug-analyzer:latest ls -la /dev/dri/

# Check OpenCL
docker run --rm --device /dev/dri:/dev/dri \
  kp14-keyplug-analyzer:latest clinfo
```

### Permission Errors

```bash
# Fix output directory permissions
sudo chown -R 1000:1000 output/

# Or run with your UID
docker run --user $(id -u):$(id -g) ...
```

### Container Won't Start

```bash
# Check logs
docker logs kp14-analyzer

# Run entrypoint manually
docker run --rm -it --entrypoint /bin/bash \
  kp14-keyplug-analyzer:latest

# Verify entrypoint script
docker run --rm kp14-keyplug-analyzer:latest cat /home/kp14/entrypoint.sh
```

## Performance Optimization

### Layer Caching

Dependencies are installed before copying application code to maximize layer cache reuse:

```dockerfile
# Copy requirements first (changes less frequently)
COPY requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt

# Copy code last (changes frequently)
COPY . /home/kp14/analyzer/
```

### BuildKit

Use Docker BuildKit for faster builds:

```bash
DOCKER_BUILDKIT=1 docker build -t kp14-keyplug-analyzer:latest .
```

### Multi-Architecture Builds

Build for multiple architectures:

```bash
docker buildx create --name kp14-builder --use
docker buildx build --platform linux/amd64,linux/arm64 \
  -t kp14-keyplug-analyzer:latest --push .
```

## Maintenance

### Update Base Image

```bash
# Pull latest Debian Bookworm
docker pull debian:bookworm-slim

# Rebuild
./docker-build.sh
```

### Update Dependencies

```bash
# Update requirements.txt
# Then rebuild
./docker-build.sh
```

### Clean Up

```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove all unused data
docker system prune -a --volumes
```

## Integration

### CI/CD Pipeline

```yaml
# Example GitLab CI
build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

test:
  stage: test
  script:
    - docker run --rm $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA test
```

### Kubernetes Deployment

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kp14-analysis
spec:
  template:
    spec:
      containers:
      - name: analyzer
        image: kp14-keyplug-analyzer:latest
        args: ["/data/input/sample.jpg"]
        volumeMounts:
        - name: input
          mountPath: /home/kp14/input
          readOnly: true
        - name: output
          mountPath: /home/kp14/output
        resources:
          limits:
            memory: "8Gi"
            cpu: "4"
      restartPolicy: Never
      volumes:
      - name: input
        persistentVolumeClaim:
          claimName: kp14-input
      - name: output
        persistentVolumeClaim:
          claimName: kp14-output
```

## Best Practices

1. **Always use versioned tags** for production deployments
2. **Mount input as read-only** to prevent tampering
3. **Set resource limits** to prevent resource exhaustion
4. **Use GPU acceleration** when available for better performance
5. **Enable health checks** for container orchestration
6. **Keep base image updated** for security patches
7. **Use named volumes** for persistent data
8. **Review logs regularly** for errors and warnings

## Support

For issues, questions, or contributions:

- Check the main [README.md](README.md)
- Review [KP14-IMPROVEMENT-PLAN.md](KP14-IMPROVEMENT-PLAN.md)
- Examine container logs: `docker logs <container-id>`
- Run self-test: `./docker-run.sh --test`

## License

Refer to the main project LICENSE file.
