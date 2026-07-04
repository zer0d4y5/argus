# PLANTED-VULNERABLE FIXTURE — DO NOT FIX. Deliberate misconfigurations for
# scanner coverage tests. See testdata/iac/labels.json.
FROM ubuntu:latest
ENV AWS_SECRET_ACCESS_KEY=AKIAFAKEFIXTUREKEY123456
RUN apt-get update && apt-get install -y --no-install-recommends curl
CMD ["bash"]
