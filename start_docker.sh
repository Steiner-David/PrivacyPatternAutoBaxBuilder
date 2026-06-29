ENV_FILE="${1:-.env}"

sudo docker run \
  --network host \
  --env-file "$ENV_FILE" \
  -e TZ=Europe/Vienna \
  -e AUTOBAX_TIMEZONE=Europe/Vienna \
  -it \
  --memory="4g" \
  --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd)":/app \
  autobaxbuilder /bin/bash
