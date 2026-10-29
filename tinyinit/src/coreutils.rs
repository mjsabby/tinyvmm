use anyhow::{Result, bail};
use std::ffi::OsString;

macro_rules! applets {
    ($($name:literal => $implementation:ident),* $(,)?) => {
        pub const APPLETS: &[&str] = &[$($name),*];

        pub fn run(name: &str, args: Vec<OsString>) -> Result<i32> {
            uucore::locale::setup_localization(name)?;
            match name {
                $($name => Ok($implementation::uumain(args.into_iter())),)*
                _ => bail!("unknown coreutils applet {name:?}"),
            }
        }
    };
}

applets! {
    "cat" => uu_cat, "chmod" => uu_chmod, "chown" => uu_chown,
    "cp" => uu_cp, "date" => uu_date, "df" => uu_df, "du" => uu_du,
    "env" => uu_env, "head" => uu_head, "id" => uu_id, "kill" => uu_kill,
    "ln" => uu_ln, "ls" => uu_ls, "mkdir" => uu_mkdir, "mv" => uu_mv,
    "nproc" => uu_nproc, "printenv" => uu_printenv, "readlink" => uu_readlink,
    "rm" => uu_rm, "sleep" => uu_sleep, "sort" => uu_sort,
    "stat" => uu_stat, "stty" => uu_stty, "tail" => uu_tail, "tee" => uu_tee,
    "touch" => uu_touch, "tty" => uu_tty, "uname" => uu_uname,
    "wc" => uu_wc, "whoami" => uu_whoami,
}
