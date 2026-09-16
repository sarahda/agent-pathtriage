# AgentCore runs on ARM64 (Graviton) ONLY. Build with --platform linux/arm64.
FROM --platform=linux/arm64 public.ecr.aws/lambda/python:3.12
COPY agent.py ${LAMBDA_TASK_ROOT}
CMD ["agent.handler"]
