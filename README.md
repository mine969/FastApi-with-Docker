# Midterm: FastAPI + Redis Login Demo

This project runs a minimal login system using FastAPI for the web app and Redis for session storage.
The app uses SQLite for user records so you do not need to run a third container.

## Services
- `web`: FastAPI app built from a Dockerfile
- `redis`: Redis 7 container from Docker Hub

## How to run
```bash
cd docker-midterm-fastapi-redis
docker compose up -d --build
docker ps
# Open http://localhost:8000
```
Register, then log in, visit `/protected`, then log out.
