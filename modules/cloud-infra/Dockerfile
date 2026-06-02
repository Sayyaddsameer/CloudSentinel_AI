FROM public.ecr.aws/lambda/python:3.11

# Install dependencies
COPY requirements.txt ${LAMBDA_TASK_ROOT}/
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.txt

# Copy Lambda handler
COPY cloud_scanner.py ${LAMBDA_TASK_ROOT}/

CMD ["cloud_scanner.lambda_handler"]
