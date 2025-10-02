# KP14 Docker Quick Start Guide

**Get started with KP14 KEYPLUG Analyzer in 3 commands**

## Prerequisites

- Docker installed and running
- Linux system with Intel CPU (optional GPU/NPU for acceleration)

## Quick Start

### 1. Build the Image (One Time)

```bash
./docker-build.sh
```

**Expected output**: Docker image built successfully with validation test

### 2. Prepare Your File

```bash
# Create input directory and copy your file
mkdir -p input
cp /path/to/suspicious-file.jpg input/
```

### 3. Run Analysis

```bash
./docker-run.sh suspicious-file.jpg
```

**Results**: Check `output/analysis_output/` directory

---

## That's It!

Your analysis is complete. Check the `output/` directory for results.

---

## Common Commands

```bash
# Run self-test
./docker-run.sh --test

# Interactive shell
./docker-run.sh --shell

# Get help
./docker-run.sh --help

# Custom settings
./docker-run.sh -s my-settings.ini file.bin

# Disable GPU
./docker-run.sh --no-gpu file.jpg
```

---

## Alternative: Docker Compose

```bash
# Build and start
docker-compose build
docker-compose up -d

# Run analysis
docker-compose exec kp14-analyzer \
  python3 /home/kp14/analyzer/main.py \
  /home/kp14/input/file.jpg

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## Troubleshooting

### Build fails?
```bash
docker system prune -a
./docker-build.sh
```

### Permission errors?
```bash
sudo chown -R 1000:1000 output/
```

### GPU not detected?
```bash
# Check host
ls -la /dev/dri/

# Check container
./docker-run.sh --shell
clinfo
```

---

## Full Documentation

- **Complete Guide**: [DOCKER.md](DOCKER.md)
- **Deployment Details**: [DOCKER-DEPLOYMENT-SUMMARY.md](DOCKER-DEPLOYMENT-SUMMARY.md)
- **Quick Reference**: [docker/README.md](docker/README.md)

---

## Support

For issues or questions:
1. Check the [DOCKER.md](DOCKER.md) troubleshooting section
2. Run `./docker-run.sh --test` to verify installation
3. Review container logs: `docker logs <container-id>`

---

**Ready to analyze? Run `./docker-run.sh <your-file>`**
