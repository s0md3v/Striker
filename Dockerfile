FROM alpine:3.10

RUN apk --update add --no-cache python3 py3-requests py3-pip py3-lxml openssl ca-certificates
RUN apk --update add --vertual build-dependencies python3-dev build-base wget git \
  && git clone https://github.com/gitadvisor/Striker.git
WORKDIR Striker

RUN pip3 install -r requirements.txt
ENTRYPOINT ["python3", "striker.py"]
CMD ["--help"]
