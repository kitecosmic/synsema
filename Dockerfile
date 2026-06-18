FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .

# Default: run a .syn file passed as argument
# Usage:
#   docker build -t syntecnia .
#   docker run syntecnia run examples/hello.syn
#   docker run syntecnia run my_agent.syn --serve
#   docker run -d syntecnia run my_agent.syn --serve   (detached, stays alive)
#   docker run -v $(pwd)/data:/data syntecnia run agent.syn --serve
ENTRYPOINT ["syntecnia"]
CMD ["version"]
