# ModSecurity-envoy
The ModSecurity-Envoy is Envoy version compiled with HTTP filter (can be opt-in/out) running ModSecurity (V3).
In other words you can run and configure WAF (ModSecurity) rules on HTTP Traffic that flows through envoy.

The most common use case is for ModSecurity-Envoy is to apply WAF on East-West traffic inside kubernetes deployments.
As Envoy is the de-facto standard proxy in kubernetes deployments and is usually deployed in every pod you can deploy
this Envoy version and Enable ModSecurity-Envoy Filter on all pods or on the most important ones.

## Prerequisites

* This repo use git-lfs so please install it from [here](https://git-lfs.github.com/) before `git clone`
* [Bazel](https://docs.bazel.build/versions/master/install-ubuntu.html#install-with-installer-ubuntu)

```bash
sudo apt-get install -y libtool cmake realpath clang-format-5.0 automake 
sudo apt-get install -y g++ flex bison curl doxygen libyajl-dev libgeoip-dev libtool dh-autoreconf libcurl4-gnutls-dev libxml2 libpcre++-dev libxml2-dev
```

## Building

To build the envoy static binary with ModSecurity-Envoy filter:

```bash
git clone git@github.com:octarinesec/ModSecurity-envoy.git
cd ModSecurity-envoy
git submodule update --init
bazel build //http-filter-modsecurity:envoy # sometimes the build timesout and you should rerun it
```

Download OWASP ModSecurity Core Rule Set (CRS). CRS is a set of generic attack
detection rules for use with ModSecurity and aims to protect web applications
from wide range of attacks. For more information check out [https://modsecurity.org/crs/](https://modsecurity.org/crs/)
 

```bash
wget https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/v3.0.2.tar.gz
tar xvzf v3.0.2.tar.gz
cp owasp-modsecurity-crs-3.0.2/crs-setup.conf.example crs-setup.conf
```

## Testing

TODO

## How it works

First let's run an echo server that we will use as our upstream

```bash
docker run -p 5555:80 kennethreitz/httpbin
```

Now let's run the envoy

```bash
sudo ./bazel-bin/http-filter-modsecurity/envoy -c envoy-modsecurity-example.yaml -l info
```

Make our first request
```bash
curl -X GET "http://127.0.0.1:8585/get" -H "accept: application/json"
```

Let's download Nikto which is the most popular Open Source web server scanner

```bash
wget https://github.com/sullo/nikto/archive/master.zip
unzip master.zip
perl nikto-master/program/nikto.pl -h localhost:5555
```

Now we can `cat /var/log/modsec_audit.log` and see all detected attacks which in production
can be piped to a SIEM of your choice or any other centralized log.

Let's try and add our own RULE as each WAF are designed to be configurable to protect
different web applications.

Paste the following line in `modsecurity-example.conf`

`SecRule ARGS:param1 "test" "id:1,deny,msg:'this',msg:'is',msg:'a',msg:'test'"`

This line will detect any url with argument ?param1=test param.

rerun envoy and execute the following command
`curl -X GET "http://127.0.0.1:8585/get?param1=test" -H "accept: application/json"`

check the logs via `tail -f` and you will see the following output

```bash
ModSecurity: Warning. Matched "Operator `Rx' with parameter `test' against variable `ARGS:param1' (Value: `test' ) [file "crs-setup.conf"] [line "7"] [id "1"] [rev ""] [msg "test"] [data ""] [severity "0"] [ver ""] [maturity "0"] [accuracy "0"] [hostname ""] [uri "/"] [unique_id "152991475598.002681"] [ref "o0,4v13,4"]
```

## Limitations

The current version only works in detection mode.
