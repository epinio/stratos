[![Unit tests](https://github.com/epinio/ui-backend/actions/workflows/main.yml/badge.svg)](https://github.com/epinio/ui-backend/actions/workflows/main.yml)

# Build

When running locally execute `npm install`
> Note - This doesn't do anything except runs a few things `postinstall`, the most import is a rejig of config files.. which is just `./build/dev-setup.js`


```
cd src/jetstream
npm run build-backend
```
> Note - This just runs `./build/bk-build.sh` under the hood


# Run

```
cd src/jetstream
EPINIO_API_URL=<epinio API URL> EPINIO_API_SKIP_SSL=<true|false> ./jetstream
```

# Template / Helm

## Environment Variables

The following envs should be provided as env vars via helm.

| Key | Required | Default | Description |
|-----|-----|---|--|
| `EPINIO_API_URL` | Yes | - | API URL of epinio instance
| `EPINIO_API_SKIP_SSL`| No (only for dev) | `false` | Skip checking for valid SSL cert when making requests to `EPINIO_API_URL`
| `CONSOLE_PROXY_CERT_PATH` | Yes | - | Certificates value
| `CONSOLE_PROXY_CERT_KEY_PATH` | Yes | - | Certificates value
| `SESSION_STORE_SECRET` | Yes (only for prod) |
| `UI_PATH` | No | `./ui` | path to UI files that are served up by Jetstream

### Building Jetstream

```
./build/bk-build.sh
```

This will create a `jetstream` binary in `src/jetstream

### Fetching UI

The UI lives in `rancher/dashboard` (until the new plugins features makes it in). Under certain conditions that repo spits out a build. That build is currently how the rancher integrated solution works. 

So to fetch the files required to be bundled (and served) with the ui backend... something like the following should work

```
wget -r https://releases.rancher.com/dashboard/<epinio ui version>/index.html
```
