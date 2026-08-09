# Local playground

Use this playground to run Caddy with Caddy Shield locally against a locally-served blocklist

## 1. Build Caddy

Build a local Caddy binary with the module:

```sh
xcaddy build --output ./caddy --with github.com/dmarcwise/caddy-shield=..
```

This creates `./caddy` in this directory.

## 2. Serve the blocklist

In a separate terminal, serve the blocklist over HTTP:

```sh
python3 -m http.server 8099 --bind 127.0.0.1
```

The initial [`blocklist.txt`](blocklist.txt) contains `127.0.0.1`, so local requests should be blocked.

## 3. Start Caddy

In another terminal, validate and run the playground configuration:

```sh
./caddy validate
./caddy run
```

## 4. Verify blocking

From a third terminal:

```sh
curl -i http://127.0.0.1:8080
```

Once the initial list has loaded, the response is:

```text
HTTP/1.1 403 Forbidden

Blocked by Shield
```

If the first request returns `200`, wait a moment for the asynchronous download and try again.

## 5. Change the decision

Replace the list with an unrelated address:

```sh
printf '192.0.2.1\n' > blocklist.txt
```

Wait a few seconds and repeat the request:

```sh
curl -i http://127.0.0.1:8080
```

It should now return:

```text
HTTP/1.1 200 OK

Request allowed
```

To verify the reverse transition, add the local address again, wait for the next refresh, and retry:

```sh
printf '127.0.0.1\n' > blocklist.txt
curl -i http://127.0.0.1:8080
```

Stop Caddy and the Python server with `Ctrl+C` when finished.
