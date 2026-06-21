FROM python:3.12-slim

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -e .

# Default: run a .syn file passed as argument
# Usage:
#   docker build -t synsema .
#   docker run synsema run examples/hello.syn
#   docker run synsema run my_agent.syn --serve
#   docker run -d synsema run my_agent.syn --serve   (detached, stays alive)
#   docker run -v $(pwd)/data:/data synsema run agent.syn --serve
ENTRYPOINT ["synsema"]
CMD ["version"]
