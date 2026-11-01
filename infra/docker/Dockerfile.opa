# OPA policy server image for the cloud profile.
#
# The Lambda functions call a shared OPA over HTTPS/HTTP (`OPA_URL`), so the
# policies must be baked into this image and redeployed whenever `policies/`
# changes. Build/push:
#
#   aws ecr get-login-password --region ap-south-1 \
#     | docker login --username AWS --password-stdin <account>.dkr.ecr.ap-south-1.amazonaws.com
#   docker build --platform linux/amd64 \
#     -f infra/docker/Dockerfile.opa \
#     -t <account>.dkr.ecr.ap-south-1.amazonaws.com/ace-opa-dev:<tag> .
#   docker push <account>.dkr.ecr.ap-south-1.amazonaws.com/ace-opa-dev:<tag>
#
# Then force a new ECS deployment so the task pulls the new image:
#   aws ecs update-service --cluster ace-opa-dev --service ace-opa-dev \
#     --force-new-deployment --region ap-south-1
FROM openpolicyagent/opa:0.63.0-static

COPY policies/ /policies/

CMD ["run", "--server", "--addr=0.0.0.0:8181", "/policies"]
