FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3 python3-pip iptables
WORKDIR /app
COPY project-memoria-detector.py requirements.txt ./
RUN pip3 install -r requirements.txt
ENTRYPOINT [ "python3", "/app/project-memoria-detector.py" ]
CMD ["-h"]
