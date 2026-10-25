# No default image: supply the reviewed official Ubuntu 24.04 LTS digest.
ARG UBUNTU_IMAGE
FROM --platform=linux/arm64 ${UBUNTU_IMAGE}
ARG UBUNTU_IMAGE
LABEL org.openlxssh.fixture="env-fixture-a" \
      org.openlxssh.fixture.base="${UBUNTU_IMAGE}"
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
# This is image-local policy-rc.d, never a host/global change. Prevent package
# installation from starting sshd and discard all image-build host keys.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 0755 /usr/sbin/policy-rc.d \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       openssh-server openssh-client openssh-sftp-server libpam-python \
       python3 ca-certificates bash procps coreutils vim-tiny tmux htop \
    && test -f /lib/security/pam_python.so \
    && test -x /usr/lib/openssh/sftp-server \
    && rm -f /etc/ssh/ssh_host_* \
    && groupadd --gid 10000 fixture \
    && useradd --uid 10000 --gid 10000 --no-create-home --home-dir /fixture/home \
       --shell /bin/bash fixture \
    && mkdir -p /opt/openlxssh-fixture \
    && dpkg-query -W > /opt/openlxssh-fixture/packages.txt \
    && rm -rf /var/lib/apt/lists/*
COPY server.py pam_fixture.py generate_data.py key_askpass.py sshd_config.in /opt/openlxssh-fixture/
COPY pam-sshd /etc/pam.d/sshd
RUN chmod 0755 /opt/openlxssh-fixture /opt/openlxssh-fixture/*.py \
    && chmod 0644 /etc/pam.d/sshd /opt/openlxssh-fixture/sshd_config.in
EXPOSE 2222
ENTRYPOINT ["python3", "/opt/openlxssh-fixture/server.py"]
