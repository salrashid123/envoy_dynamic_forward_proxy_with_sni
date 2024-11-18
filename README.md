
### Envoy Dynamic Forward Proxy configuration with Downstream SNI for Google APIs and HTTPBin

Simple envoy configuration which over one listener select the SNI certificate to present to the calling downstream client and then based on the intended host, proxies the client's request to the upstream. 

`client -> (TLS) -> Envoy --> (TLS) -> Upstream`


The various envoy Filters used in this example are:

* [type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/listener/tls_inspector/v3/tls_inspector.proto)
* [type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/dynamic_forward_proxy/v3/dynamic_forward_proxy.proto)


The reason i'm writing this is it took me sometime to get it right (or right as far as i know)


Anyway, to use this, clone the repo, download envoy (on linux 

```bash
docker cp `docker create envoyproxy/envoy-dev:latest`:/usr/local/bin/envoy /tmp/
```

Run envoy

```bash
/tmp/envoy -c envoy_server.yaml -l debug
```

Then for either http or grpc


#### HTTP

Run

```bash
curl  -vvv  --cacert certs/root-ca.crt \
  -H "Host: httpbin.org" --connect-to  httpbin.org:443:127.0.0.1:8081 https://httpbin.org/get
```


What you'll see is a connection to the localhost envoy over `:8081`  but the certificate presented is using the SNI information (eg, its `httpbin.org`...well the fake one i have signed).  Once the connection is established to envoy, a synthetic header is added on before sending the traffic out to the upstream

```text
$ curl  -vvv  --cacert certs/root-ca.crt \
  -H "Host: httpbin.org" --connect-to  httpbin.org:443:127.0.0.1:8081 https://httpbin.org/get
  
* Connecting to hostname: 127.0.0.1
* Connecting to port: 8081
*   Trying 127.0.0.1:8081...
* Connected to 127.0.0.1 (127.0.0.1) port 8081 (#0)
* ALPN: offers h2
* ALPN: offers http/1.1
*  CAfile: certs/root-ca.crt
*  CApath: /etc/ssl/certs

* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
* ALPN: server did not agree on a protocol. Uses default.
* Server certificate:
*  subject: C=US; O=Google; OU=Enterprise; CN=httpbin.org
*  start date: May  1 21:21:44 2022 GMT
*  expire date: Aug  8 21:21:44 2024 GMT
*  subjectAltName: host "httpbin.org" matched cert's "httpbin.org"
*  issuer: C=US; O=Google; OU=Enterprise; CN=Enterprise Subordinate CA
*  SSL certificate verify ok.
* TLSv1.2 (OUT), TLS header, Supplemental data (23):

> GET /get HTTP/1.1
> Host: httpbin.org
> User-Agent: curl/7.85.0
> Accept: */*
> 

< HTTP/1.1 200 OK
< date: Thu, 20 Oct 2022 16:55:32 GMT
< content-type: application/json
< content-length: 325
< server: envoy
< access-control-allow-origin: *
< access-control-allow-credentials: true
< x-envoy-upstream-service-time: 35
< 
{
  "args": {}, 
  "headers": {
    "Accept": "*/*", 
    "Host": "httpbin.org", 
    "User-Agent": "curl/7.85.0", 
    "X-Amzn-Trace-Id": "Root=1-63517d84-33d8b117076319986e49a085", 
    "X-Envoy-Expected-Rq-Timeout-Ms": "15000", 
    "X-Foo": "bar"
  }, 
  "origin": "108.56.239.251", 
  "url": "https://httpbin.org/get"
}

```

The envoy logs will show the SNI TLS Inspector:

```log
[2022-10-20 12:55:31.939][1023746][debug][filter] [source/extensions/filters/listener/tls_inspector/tls_inspector.cc:116] tls:onServerName(), requestedServerName: httpbin.org
[2022-10-20 12:55:31.939][1023746][debug][filter] [source/extensions/filters/listener/http_inspector/http_inspector.cc:53] http inspector: new connection accepted
```

Then the inbound request

```log
[2022-10-20 12:55:31.939][1023746][debug][conn_handler] [source/server/active_tcp_listener.cc:142] [C0] new connection from 127.0.0.1:45714
[2022-10-20 12:55:31.942][1023746][debug][http] [source/common/http/conn_manager_impl.cc:299] [C0] new stream
[2022-10-20 12:55:31.942][1023746][debug][http] [source/common/http/conn_manager_impl.cc:904] [C0][S17173218376188407192] request headers complete (end_stream=true):
':authority', 'httpbin.org'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/7.85.0'
'accept', '*/*'
```

which uses the DNS dynamic lookup for `httpbin.org`

```log
[2022-10-20 12:55:31.943][1023746][debug][forward_proxy] [source/extensions/filters/http/dynamic_forward_proxy/proxy_filter.cc:161] [C0][S17173218376188407192] waiting to load DNS cache entry
[2022-10-20 12:55:31.943][1023738][debug][forward_proxy] [source/extensions/common/dynamic_forward_proxy/dns_cache_impl.cc:284] starting main thread resolve for host='httpbin.org' dns='httpbin.org' port='443'

[2022-10-20 12:55:31.980][1023738][debug][forward_proxy] [source/extensions/common/dynamic_forward_proxy/dns_cache_impl.cc:307] main thread resolve complete for host 'httpbin.org': [34.199.239.80:0, 52.45.189.24:0, 18.207.88.57:0, 54.236.79.58:0]

[2022-10-20 12:55:31.980][1023738][debug][forward_proxy] [source/extensions/common/dynamic_forward_proxy/dns_cache_impl.cc:374] host 'httpbin.org' address has changed from <empty> to 34.199.239.80:443

[2022-10-20 12:55:31.980][1023738][debug][upstream] [source/extensions/clusters/dynamic_forward_proxy/cluster.cc:112] Adding host info for httpbin.org


[2022-10-20 12:55:31.980][1023738][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:1149] membership update for TLS cluster dynamic_forward_proxy_cluster added 1 removed 0
[2022-10-20 12:55:31.980][1023738][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:1155] re-creating local LB for TLS cluster dynamic_forward_proxy_cluster
[2022-10-20 12:55:31.980][1023747][debug][upstream] [source/common/upstream/cluster_manager_impl.cc:1149] membership update for TLS cluster dynamic_forward_proxy_cluster added 1 removed 0
```

THen a connection with the new header added on to it intended for the actual upstream service

```log
[2022-10-20 12:55:31.981][1023746][debug][forward_proxy] [source/extensions/filters/http/dynamic_forward_proxy/proxy_filter.cc:206] [C0][S17173218376188407192] load DNS cache complete, continuing after adding resolved host: httpbin.org
[2022-10-20 12:55:31.981][1023746][debug][router] [source/common/router/router.cc:467] [C0][S17173218376188407192] cluster 'dynamic_forward_proxy_cluster' match for URL '/get'
[2022-10-20 12:55:31.981][1023746][debug][router] [source/common/router/router.cc:670] [C0][S17173218376188407192] router decoding headers:
':authority', 'httpbin.org'
':path', '/get'
':method', 'GET'
':scheme', 'https'
'user-agent', 'curl/7.85.0'
'accept', '*/*'
'x-forwarded-proto', 'https'
'x-request-id', '97fac3b9-1a4c-48fd-9cd5-92af78df279a'
'x-envoy-expected-rq-timeout-ms', '15000'
'x-foo', 'bar'

[2022-10-20 12:55:31.982][1023746][debug][connection] [source/common/network/connection_impl.cc:912] [C2] connecting to 34.199.239.80:443
[2022-10-20 12:55:31.982][1023746][debug][connection] [source/common/network/connection_impl.cc:931] [C2] connection in progress
[2022-10-20 12:55:31.988][1023746][debug][connection] [source/common/network/connection_impl.cc:683] [C2] connected
[2022-10-20 12:55:32.007][1023746][debug][happy_eyeballs] [source/common/network/happy_eyeballs_connection_impl.cc:487] [C1] address=1
[2022-10-20 12:55:32.008][1023746][debug][client] [source/common/http/codec_client.cc:89] [C1] connected
[2022-10-20 12:55:32.008][1023746][debug][pool] [source/common/conn_pool/conn_pool_base.cc:305] [C1] attaching to next stream
[2022-10-20 12:55:32.008][1023746][debug][pool] [source/common/conn_pool/conn_pool_base.cc:177] [C1] creating stream
[2022-10-20 12:55:32.008][1023746][debug][router] [source/common/router/upstream_request.cc:422] [C0][S17173218376188407192] pool ready
[2022-10-20 12:55:32.017][1023746][debug][router] [source/common/router/router.cc:1351] [C0][S17173218376188407192] upstream headers complete: end_stream=false
```

then a response back from the upstream sent back to the client
```log
[2022-10-20 12:55:32.017][1023746][debug][http] [source/common/http/conn_manager_impl.cc:1516] [C0][S17173218376188407192] encoding headers via codec (end_stream=false):
':status', '200'
'date', 'Thu, 20 Oct 2022 16:55:32 GMT'
'content-type', 'application/json'
'content-length', '325'
'server', 'envoy'
'access-control-allow-origin', '*'
'access-control-allow-credentials', 'true'
'x-envoy-upstream-service-time', '35'

[2022-10-20 12:55:32.017][1023746][debug][client] [source/common/http/codec_client.cc:126] [C1] response complete
```

### gRPC (Google Pubsub)

You can also point google cloud clients against envoy.  

To use this sample, use this you must have a project setup with a topic (called `topic1` and the ability to post a message to that topic.

see `client/` folder on use.  The server-side envoy configuration is already set and the TLS certificate loaded is for `pubsub.googleapis.com`.

---

For more info about envoy, see

- [Envoy TLS proxy for gRPC](https://github.com/salrashid123/envoy_grpc_tls_bridge/tree/main/grpc_envoy_proxy)
- [Filtering gRPC Messages using Envoy](https://github.com/salrashid123/envoy_grpc_decode)
- [Monitoring GCP API Latency locally using Envoy](https://github.com/salrashid123/envoy_gcp_monitoring)
