FROM golang:latest 

# NOTE: It is expected from you to build the binary beforehand
COPY ebpf-map-metrics-demo /usr/bin/demo

ENTRYPOINT [ "/usr/bin/demo" ]
