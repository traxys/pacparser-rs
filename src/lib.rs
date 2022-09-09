use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};

use boa_engine::{object::FunctionBuilder, property::Attribute, Context, JsResult, JsValue};
use gc::{Finalize, Trace};
use ipnet::Ipv4Net;
use local_ip_address::local_ip;
use regex::Regex;
use url::Url;

trait JsResultExt<T> {
    fn to_string(self, ctx: &mut Context) -> std::result::Result<T, Error>;
}

impl<T> JsResultExt<T> for JsResult<T> {
    fn to_string(self, ctx: &mut Context) -> std::result::Result<T, Error> {
        self.map_err(|err| {
            Error::JsError(
                err.to_string(ctx)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| "could not format error".into()),
            )
        })
    }
}

pub struct PacParser {
    js_ctx: Context,
}

pub struct PacFile<'ctx> {
    ctx: &'ctx mut PacParser,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("js error: {0}")]
    JsError(String),
    #[error("Proxy entry was invalid: {0}")]
    MalformedProxyEntry(String),
    #[error("Pac file did not return a String")]
    InvalidPacReturn,
    #[error("Url has no host")]
    NoHost,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyType {
    Proxy,
    Socks,
    Http,
    Https,
    Socks4,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyEntry {
    Direct,
    Proxied {
        ty: ProxyType,
        host: String,
        port: String,
    },
}

impl FromStr for ProxyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "PROXY" => Ok(Self::Proxy),
            "SOCKS" => Ok(Self::Socks),
            "HTTP" => Ok(Self::Http),
            "HTTPS" => Ok(Self::Https),
            "SOCKS4" => Ok(Self::Socks4),
            "SOCKS5" => Ok(Self::Socks5),
            _ => Err(Error::MalformedProxyEntry(format!("Unknown type `{}`", s))),
        }
    }
}

fn dns_domain_is(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    match args {
        [a, b] => {
            let (a, b) = (a.to_string(ctx)?, b.to_string(ctx)?);

            Ok(a.ends_with(&*b).into())
        }
        _ => unreachable!("expected two arguments"),
    }
}

fn is_plain_hostname(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    match args {
        [name] => {
            let n = name.to_string(ctx)?;
            Ok(match Url::parse(&n) {
                Err(url::ParseError::RelativeUrlWithoutBase) => !n.contains('.'),
                Err(_) => false,
                Ok(v) => v.host_str().map(|n| !n.contains('.')).unwrap_or(false),
            }
            .into())
        }
        _ => unreachable!("expected one arguments"),
    }
}

fn is_in_inet(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    match args {
        [host, net, mask] => {
            let net: Ipv4Addr = net
                .to_string(ctx)?
                .parse()
                .map_err(|err| format!("invalid ip addr: {err:?}"))?;

            let mask: Ipv4Addr = mask
                .to_string(ctx)?
                .parse()
                .map_err(|err| format!("invalid ip mask: {err:?}"))?;
            let prefix_len = u32::from_ne_bytes(mask.octets()).count_ones();

            let net = Ipv4Net::new(net, prefix_len as u8).expect("prefix should not be a problem");

            match host.to_string(ctx)?.parse() {
                Err(_) => {
                    let ip = dns_resolve(host, &[host.clone()], ctx)?
                        .to_string(ctx)?
                        .parse()
                        .expect("dns resolve should return an ip");

                    Ok(net.contains::<&Ipv4Addr>(&ip).into())
                }
                Ok(ip) => Ok(net.contains::<&Ipv4Addr>(&ip).into()),
            }
        }
        _ => unreachable!("expected three arguments"),
    }
}

fn dns_resolve(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    match args {
        [name] => {
            let lookup = dns_lookup::lookup_host(&name.to_string(ctx)?)
                .map_err(|err| format!("dns error: {err:?}"))?;

            let v4 = lookup.iter().find(|ip| ip.is_ipv4());

            match v4 {
                None => todo!("handle ipv6"),
                Some(v4) => Ok(v4.to_string().into()),
            }
        }
        _ => unreachable!("expected one argument"),
    }
}

fn my_ip(_: &JsValue, _: &[JsValue], _: &mut Context) -> JsResult<JsValue> {
    let my_ip = local_ip().map_err(|err| format!("Could not get IP addr: {err:?}"))?;

    Ok(my_ip.to_string().into())
}

fn local_host_or_domain_is(_: &JsValue, args: &[JsValue], ctx: &mut Context) -> JsResult<JsValue> {
    match args {
        [a, b] => {
            let (a, b) = (a.to_string(ctx)?, b.to_string(ctx)?);

            Ok(b.starts_with(&*a).into())
        }
        _ => unreachable!("expected two arguments"),
    }
}

#[derive(Trace, Finalize, Debug)]
struct RegexCache {
    #[unsafe_ignore_trace]
    cache: HashMap<String, Regex>,
}

impl RegexCache {
    fn matches(&mut self, str: &str, regex: &str) -> JsResult<bool> {
        match self.cache.get(regex) {
            None => {
                let re = Regex::new(&format!("^{regex}$"))
                    .map_err(|err| format!("regex error: {err:?}"))?;
                let is_match = re.is_match(str);
                self.cache.insert(regex.into(), re);
                Ok(is_match)
            }
            Some(re) => Ok(re.is_match(str)),
        }
    }
}

impl PacParser {
    pub fn new() -> Result<Self> {
        let mut js_ctx = Context::builder().build();

        js_ctx.register_global_builtin_function("dnsDomainIs", 2, dns_domain_is);
        js_ctx.register_global_builtin_function("isPlainHostName", 1, is_plain_hostname);
        js_ctx.register_global_builtin_function("isInNet", 3, is_in_inet);
        js_ctx.register_global_builtin_function("dnsResolve", 1, dns_resolve);
        js_ctx.register_global_builtin_function("myIpAddress", 0, my_ip);
        js_ctx.register_global_builtin_function("localHostOrDomainIs", 2, local_host_or_domain_is);

        let cache = RegexCache {
            cache: HashMap::new(),
        };

        let sh_exp = FunctionBuilder::closure_with_captures(
            &mut js_ctx,
            |_, args, cache, ctx| match args {
                [str, regex] => cache
                    .matches(&*str.to_string(ctx)?, &*regex.to_string(ctx)?)
                    .map(Into::into),
                _ => unreachable!("takes two arguments"),
            },
            cache,
        )
        .length(2)
        .name("shExpMatch")
        .build();
        js_ctx.register_global_property("shExpMatch", sh_exp, Attribute::all());

        Ok(Self { js_ctx })
    }

    pub fn load<D: AsRef<str>>(&mut self, file: D) -> Result<PacFile> {
        self.js_ctx
            .eval(&format!(
                "function pac(__url, __host) {{ {}; return FindProxyForURL(__url, __host); }}",
                file.as_ref()
            ))
            .to_string(&mut self.js_ctx)?;

        Ok(PacFile { ctx: self })
    }
}

impl<'ctx> PacFile<'ctx> {
    pub fn find_proxy(&mut self, url: &Url) -> Result<Vec<ProxyEntry>> {
        let host = url.host_str().ok_or(Error::NoHost)?;

        let pac = self
            .ctx
            .js_ctx
            .global_object()
            .clone()
            .get("pac", &mut self.ctx.js_ctx)
            .to_string(&mut self.ctx.js_ctx)?;

        let result = pac
            .as_callable()
            .expect("pac should be callable")
            .call(
                &pac,
                &[url.as_str().into(), host.into()],
                &mut self.ctx.js_ctx,
            )
            .to_string(&mut self.ctx.js_ctx)?;

        let result = result.as_string().ok_or(Error::InvalidPacReturn)?;

        result
            .split(';')
            .map(|part| {
                let part = part.trim();
                if let Some(x) = part.strip_prefix("DIRECT") {
                    assert!(x.trim().is_empty(), "DIRECT with host is not supported");
                    Ok(ProxyEntry::Direct)
                } else {
                    let types = &["PROXY", "SOCKS", "HTTP", "HTTPS", "SOCKS4", "SOCKS5"];
                    for ty in types {
                        if let Some(proxy) = part.strip_prefix(ty) {
                            let proxy = proxy.trim();
                            let colon = proxy.find(':').ok_or_else(|| {
                                Error::MalformedProxyEntry("No colon in entry".into())
                            })?;
                            let (host, port) = proxy.trim().split_at(colon);
                            return Ok(ProxyEntry::Proxied {
                                ty: ty.parse()?,
                                host: host.into(),
                                port: port[1..].into(),
                            });
                        }
                    }
                    Err(Error::MalformedProxyEntry("No type matched".into()))
                }
            })
            .collect()
    }
}

impl<'ctx> Drop for PacFile<'ctx> {
    fn drop(&mut self) {
        if let Err(e) = self.ctx.js_ctx.eval("pac = undefined;") {
            log::warn!("Could not erease pac function: {:?}", e);
        }
    }
}

#[cfg(test)]
mod test {
    use url::Url;

    use crate::{PacParser, ProxyEntry, ProxyType};

    macro_rules! pac {
        ($code:literal) => {
            concat!("function FindProxyForURL(url, host) { ", $code, " } ")
        };
        ($code:literal, $($tt:tt)*) => {{
            let code = format!($code, $($tt)*);
            format!("function FindProxyForURL(url, host) {{ {} }} ", code)
        }};
    }

    macro_rules! define_pac {
        ($name:ident, $code:literal) => {
            static $name: &str = pac!($code);
        };
    }

    define_pac! {DIRECT, r#"return "DIRECT";"#}
    define_pac! {SIMPLE, r#"return "PROXY 127.0.0.1:8118; DIRECT";"#}

    #[test]
    fn init_fini() {
        PacParser::new().unwrap();
    }

    #[test]
    fn load_direct() {
        let mut parser = PacParser::new().unwrap();
        parser.load(DIRECT).unwrap();
    }

    #[test]
    fn load_simple() {
        let mut parser = PacParser::new().unwrap();
        parser.load(SIMPLE).unwrap();
    }

    #[test]
    fn run_direct() {
        let mut parser = PacParser::new().unwrap();
        let mut pac = parser.load(DIRECT).unwrap();
        let proxy = pac
            .find_proxy(&Url::parse("http://localhost").unwrap())
            .unwrap();

        assert_eq!(proxy, vec![ProxyEntry::Direct]);
    }

    #[test]
    fn run_simple() {
        let mut parser = PacParser::new().unwrap();
        let mut pac = parser.load(SIMPLE).unwrap();
        let proxy = pac
            .find_proxy(&Url::parse("http://localhost").unwrap())
            .unwrap();

        assert_eq!(
            proxy,
            vec![
                ProxyEntry::Proxied {
                    ty: ProxyType::Proxy,
                    host: "127.0.0.1".into(),
                    port: "8118".into(),
                },
                ProxyEntry::Direct
            ]
        );
    }

    macro_rules! define_pac_test {
        ($name:ident, $condition:literal, $input:literal) => {
            #[test]
            fn $name() {
                let mut parser = PacParser::new().unwrap();
                let pac = pac!(
                    r#"
                    if ({})
                        return "PROXY 1:80";
                    return "DIRECT""#,
                    $condition
                );
                let mut pac = parser.load(pac).unwrap();

                let proxy = pac.find_proxy(&Url::parse($input).unwrap()).unwrap();

                assert_eq!(
                    proxy,
                    vec![ProxyEntry::Proxied {
                        ty: ProxyType::Proxy,
                        host: "1".into(),
                        port: "80".into()
                    }]
                );
            }
        };
    }

    define_pac_test! {
        dns_domain,
        r#"dnsDomainIs(host, "intranet.domain.com")"#,
        "http://intranet.domain.com"
    }

    define_pac_test! {
        sh_expr_exact,
        r#"shExpMatch(host, "(.*.adcdom.com|abcdom.com)")"#,
        "http://abcdom.com"
    }

    define_pac_test! {
        sh_expr_repeat,
        r#"shExpMatch(host, "(.*.abcdom.com|abcdom.com)")"#,
        "http://foo.abcdom.com"
    }

    define_pac_test! {
        substring,
        r#"url.substring(0, 4) == "ftp:""#,
        "ftp://thing.please"
    }

    define_pac_test! {
        is_in_net,
        r#"isInNet(host, "127.0.0.0", "255.0.0.0")"#,
        "http://localhost"
    }

    define_pac_test! {
        is_in_net_resolve,
        r#"isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")"#,
        "http://localhost"
    }

    define_pac_test! {
        my_ip,
        r#"isInNet(myIpAddress(), "192.168.0.0", "255.255.0.0")"#,
        "http://localhost"
    }

    define_pac_test! {
        host_or_domain_exact,
        r#"localHostOrDomainIs(host, "www.mozilla.org")"#,
        "http://www.mozilla.org"
    }

    define_pac_test! {
        host_or_domain_prefix,
        r#"localHostOrDomainIs(host, "www.mozilla.org")"#,
        "http://www"
    }
}
