# Ubuntu digest was resolved/approved by the primary from the official registry.
# No Docker execution until explicit engine-ready instruction after human license handling.
FROM docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends openjdk-21-jdk-headless python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/multiprompt
COPY inputs.lock.json fetch_inputs.py ./
RUN python3 fetch_inputs.py --authorized-download --destination /opt/verified-inputs
COPY src ./src
RUN mkdir /opt/classes /opt/runtime-libs \
    && cp /opt/verified-inputs/sshd-core-2.20.0.jar /opt/runtime-libs/ \
    && cp /opt/verified-inputs/sshd-common-2.20.0.jar /opt/runtime-libs/ \
    && cp /opt/verified-inputs/slf4j-api-1.7.36.jar /opt/runtime-libs/ \
    && cp /opt/verified-inputs/jcl-over-slf4j-1.7.36.jar /opt/runtime-libs/ \
    && cp /opt/verified-inputs/slf4j-nop-1.7.36.jar /opt/runtime-libs/ \
    && javac -proc:none --release 21 -Xlint:all -d /opt/classes -cp '/opt/runtime-libs/*' \
       src/org/openlxssh/fixture/FixtureServer.java src/org/openlxssh/fixture/FixtureContractTest.java \
    && java -Xmx128m -cp '/opt/classes:/opt/runtime-libs/*' org.openlxssh.fixture.FixtureContractTest

FROM docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d
LABEL org.openlxssh.fixture="auth-mina-fixture-a" \
      org.openlxssh.fixture.base="docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d"
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends openjdk-21-jre-headless python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10000 fixture \
    && useradd --uid 10000 --gid 10000 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin fixture \
    && mkdir /opt/multiprompt \
    && dpkg-query -W -f='${Package}\t${Version}\n' > /opt/multiprompt/packages.txt
COPY --from=build /opt/classes /opt/multiprompt/classes
COPY --from=build /opt/runtime-libs /opt/multiprompt/lib
COPY inputs.lock.json control.py /opt/multiprompt/
COPY licenses /opt/multiprompt/licenses
USER 10000:10000
WORKDIR /opt/multiprompt
EXPOSE 2222
ENTRYPOINT ["java", "-XX:ActiveProcessorCount=2", "-XX:+DisableAttachMechanism", "-XX:-UsePerfData", "-XX:ErrorFile=/dev/null", "-Xms32m", "-Xmx256m", "-cp", "/opt/multiprompt/classes:/opt/multiprompt/lib/*", "org.openlxssh.fixture.FixtureServer"]
CMD ["serve", "--authorized-run"]
