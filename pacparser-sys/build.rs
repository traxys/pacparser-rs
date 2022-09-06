use std::{fs::OpenOptions, path::Path, process::Command};

macro_rules! js_source {
    ($f:literal) => {
        concat!("src/pacparser/src/spidermonkey/js/src/", $f)
    };
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("no out dir");
    let out_dir = Path::new(&out_dir);
    let cc = option_env!("CC").unwrap_or("cc");

    Command::new(cc)
        .args([js_source!("jscpucfg.c"), "-o"])
        .arg(out_dir.join("jscpucfg"))
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    let jscpufg_header = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_dir.join("jsautocfg.h"))
        .unwrap();

    Command::new(out_dir.join("jscpucfg"))
        .stdout(jscpufg_header)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    Command::new(cc)
        .args([js_source!("jskwgen.c"), "-o"])
        .arg(out_dir.join("jskwgen"))
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    let jskw_header = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_dir.join("jsautokw.h"))
        .unwrap();

    Command::new(out_dir.join("jskwgen"))
        .stdout(jskw_header)
        .spawn()
        .unwrap()
        .wait()
        .unwrap();

    cc::Build::new()
        .define("XP_UNIX", None)
        .define("SVR4", None)
        .define("SYSV", None)
        .define("_BSD_SOURCE", None)
        .define("POSIX_SOURCE", None)
        .define("HAVE_LOCALTIME_R", None)
        .define("HAVE_VA_COPY", None)
        .define("VA_COPY", "va_copy")
        .define("DEBUG", None)
        .define("EDITLINE", None)
        .define("PIC", None)
        .include(out_dir)
        .files(&[
            js_source!("jsapi.c"),
            js_source!("jsarena.c"),
            js_source!("jsarray.c"),
            js_source!("jsatom.c"),
            js_source!("jsbool.c"),
            js_source!("jscntxt.c"),
            js_source!("jsdate.c"),
            js_source!("jsdbgapi.c"),
            js_source!("jsdhash.c"),
            js_source!("jsdtoa.c"),
            js_source!("jsemit.c"),
            js_source!("jsexn.c"),
            js_source!("jsfun.c"),
            js_source!("jsgc.c"),
            js_source!("jshash.c"),
            js_source!("jsinterp.c"),
            js_source!("jsiter.c"),
            js_source!("jslock.c"),
            js_source!("jslog2.c"),
            js_source!("jslong.c"),
            js_source!("jsmath.c"),
            js_source!("jsnum.c"),
            js_source!("jsobj.c"),
            js_source!("jsopcode.c"),
            js_source!("jsparse.c"),
            js_source!("jsprf.c"),
            js_source!("jsregexp.c"),
            js_source!("jsscan.c"),
            js_source!("jsscope.c"),
            js_source!("jsscript.c"),
            js_source!("jsstr.c"),
            js_source!("jsutil.c"),
            js_source!("jsxdrapi.c"),
            js_source!("jsxml.c"),
            js_source!("prmjtime.c"),
        ])
        .warnings(false)
        .compile("js");

    cc::Build::new()
        .file("src/pacparser/src/pacparser.c")
        .warnings(false)
        .include(js_source!(""))
        .include(out_dir)
        .define("XP_UNIX", None)
        .compile("pacparser");

    let bindings = bindgen::Builder::default()
        .header("src/pacparser/src/pacparser.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("could not generate bindings");

    bindings
        .write_to_file(out_dir.join("pacparser.rs"))
        .expect("could not write bindings");
}
