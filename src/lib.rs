use std::{
    ffi::{c_void, CStr, CString, NulError},
    marker::PhantomData,
    os::unix::prelude::OsStrExt,
    path::Path,
    str::Utf8Error,
    sync::atomic::{self, AtomicBool},
};

pub struct PacParser {
    __private: PhantomData<*const c_void>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Pac Parser returned an error")]
    PacParse,
    #[error("The library is already in use")]
    InUse,
    #[error("The supplied string contains a NULL byte")]
    NullError(#[from] NulError),
    #[error("Proxy is not a valid String")]
    InvalidProxy(#[from] Utf8Error),
}

static IS_INIT: AtomicBool = AtomicBool::new(false);

impl PacParser {
    pub fn new() -> Result<Self, Error> {
        if IS_INIT
            .compare_exchange(
                false,
                true,
                atomic::Ordering::Acquire,
                atomic::Ordering::Acquire,
            )
            .is_err()
        {
            return Err(Error::InUse);
        }

        unsafe {
            if pacparser_sys::pacparser_init() == 0 {
                return Err(Error::PacParse);
            };
        }
        Ok(Self {
            __private: PhantomData,
        })
    }

    pub fn load_string(&mut self, s: &str) -> Result<PacFile<'_>, Error> {
        let c_str = CString::new(s)?;
        unsafe {
            match pacparser_sys::pacparser_parse_pac_string(c_str.as_ptr()) {
                0 => Err(Error::PacParse),
                _ => Ok(PacFile { ctx: self }),
            }
        }
    }

    pub fn load_path<P: AsRef<Path>>(&mut self, path: P) -> Result<PacFile, Error> {
        let p = CString::new(path.as_ref().as_os_str().as_bytes())?;
        unsafe {
            match pacparser_sys::pacparser_parse_pac_file(p.as_ptr()) {
                0 => Err(Error::PacParse),
                _ => Ok(PacFile { ctx: self }),
            }
        }
    }

    pub fn set_ip(&mut self, ip: &str) -> Result<(), Error> {
        let s = CString::new(ip)?;
        unsafe {
            match pacparser_sys::pacparser_setmyip(s.as_ptr()) {
                0 => Err(Error::PacParse),
                _ => Ok(()),
            }
        }
    }
}

impl Drop for PacParser {
    fn drop(&mut self) {
        IS_INIT.store(false, atomic::Ordering::Release);
        unsafe { pacparser_sys::pacparser_cleanup() }
    }
}

pub struct PacFile<'ctx> {
    ctx: &'ctx mut PacParser,
}

impl<'ctx> PacFile<'ctx> {
    pub fn set_ip(&mut self, ip: &str) -> Result<(), Error> {
        self.ctx.set_ip(ip)
    }

    pub fn find_proxy(&mut self, url: &str, host: &str) -> Result<&str, Error> {
        let url = CString::new(url)?;
        let host = CString::new(host)?;

        let proxy = unsafe { pacparser_sys::pacparser_find_proxy(url.as_ptr(), host.as_ptr()) };

        if proxy.is_null() {
            Err(Error::PacParse)
        } else {
            unsafe { Ok(CStr::from_ptr(proxy).to_str()?) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::PacParser;
    use serial_test::serial;
    use url::Url;

    macro_rules! PAC_FILE {
        ($path:literal) => {
            pub static PAC_TEST_FILE: &str = include_str!(concat!("../", $path));
            pub static PAC_TEST_FILE_PATH: &str = $path;
        };
    }

    PAC_FILE! {"pacparser-sys/src/pacparser/tests/proxy.pac"}

    #[test]
    #[serial]
    fn init_fini() {
        PacParser::new().unwrap();
    }

    #[test]
    #[serial]
    fn load_test_string() {
        let mut lib = PacParser::new().unwrap();
        lib.load_string(PAC_TEST_FILE).unwrap();
    }

    #[test]
    #[serial]
    fn load_test_path() {
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut lib = PacParser::new().unwrap();
        lib.load_path(workspace.join(PAC_TEST_FILE_PATH)).unwrap();
    }

    #[test]
    #[serial]
    fn with_default_ip() {
        macro_rules! assert_url {
            ($pac:expr, $url:literal, $proxy:literal) => {
                let url = Url::parse($url).unwrap();

                assert_eq!(
                    $pac.find_proxy(url.as_str(), url.host_str().unwrap())
                        .unwrap(),
                    $proxy,
                )
            };
        }

        let mut lib = PacParser::new().unwrap();
        let mut pac = lib.load_string(PAC_TEST_FILE).unwrap();

        assert_url!(pac, "http://host1", "plainhost/.manugarg.com");
        assert_url!(pac, "http://www1.manugarg.com", "plainhost/.manugarg.com");
        assert_url!(pac, "http://www.manugarg.org/test'o'rama", "URLHasQuotes");
        assert_url!(pac, "http://manugarg.externaldomain.com", "externaldomain");
        // Internet Required
        assert_url!(pac, "http://www.google.com", "isResolvable");
        assert_url!(pac, "https://www.somehost.com", "secureUrl");
        /*
        return END OF SCRIPT ??
        assert_url!(
            pac,
            "http://www.notresolvabledomainXXX.com",
            "isNotResolvable"
        ); */
    }

    #[test]
    #[serial]
    fn with_changed_ip() {
        macro_rules! assert_url {
            ($pac:expr, $ip:literal, $url:literal, $proxy:literal) => {
                $pac.set_ip($ip).unwrap();
                let url = Url::parse($url).unwrap();

                assert_eq!(
                    $pac.find_proxy(url.as_str(), url.host_str().unwrap())
                        .unwrap(),
                    $proxy,
                )
            };
        }

        let mut lib = PacParser::new().unwrap();
        let mut pac = lib.load_string(PAC_TEST_FILE).unwrap();

        assert_url!(
            pac,
            "3ffe:8311:ffff:1:0:0:0:0",
            "http://www.somehost.com",
            "3ffe:8311:ffff"
        );
        assert_url!(pac, "0.0.0.0", "http://www.google.co.in", "END-OF-SCRIPT");
        assert_url!(pac, "10.10.100.112", "http://www.somehost.com", "10.10.0.0");
    }
}
