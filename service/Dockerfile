FROM bundlecrypt

ARG HOME_DIR=/usr/local/
ARG BUNDLE_CONFIGS_PATH=/configs

WORKDIR ${HOME_DIR}src
COPY service/*.* service/

RUN mkdir -p ${BUNDLE_CONFIGS_PATH}

RUN python3.8 -m venv /
RUN /venv/bin/pip install -r ${HOME_DIR}/src/service/requirements.txt

ENV PYTHONPATH="${HOME_DIR}/src/bundlecrypt:${HOME_DIR}/src:${HOME_DIR}/src/service"
RUN chmod +x ./service/entrypoint.sh

ENTRYPOINT [ "./service/entrypoint.sh" ]
