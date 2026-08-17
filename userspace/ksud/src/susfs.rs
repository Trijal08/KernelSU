//! Per-app SusFS pusher.
//!
//! Reads the framework-generated plan (`SUSFS_PLAN_PATH`) and applies per-uid
//! SusFS rules via the `SYS_reboot` backdoor (same channel `ksu_susfs` uses:
//! magic1 = 0xDEADBEEF, magic2 = SUSFS_MAGIC, cmd, &struct). Runs as root at
//! post-fs-data. The framework produces the *values* (back-dated times, uname,
//! cmdline); here we do the device-side `stat()` + the uid-0 supercalls.
//!
//! NOTE: the `#[repr(C)]` structs below MUST stay byte-identical to the kernel
//! (`include/linux/susfs.h`) and the userspace copies in susfs4ksu. `target_uid`
//! is appended AFTER `err` in every struct — legacy commands copy up to
//! `offsetof(target_uid)`, the `*_UID` commands copy the full struct.

#![allow(clippy::unreadable_literal, dead_code)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::MetadataExt;

const KSU_INSTALL_MAGIC1: libc::c_long = 0xDEADBEEF;
const SUSFS_MAGIC: libc::c_long = 0xFAFAFAFA;

// --- command numbers (mirror include/linux/susfs_def.h, incl. our *_UID additions) ---
const CMD_ADD_SUS_KSTAT_STATICALLY_UID: libc::c_long = 0x55573;
const CMD_SET_FILE_TIME_OFFSET_UID: libc::c_long = 0x55574;
const CMD_SET_UPTIME_OFFSET_UID: libc::c_long = 0x55575;
const CMD_ADD_OPEN_REDIRECT_UID: libc::c_long = 0x555c1;
const CMD_SET_UNAME_UID: libc::c_long = 0x55591;
const CMD_SET_CMDLINE_OR_BOOTCONFIG_UID: libc::c_long = 0x555b1;
const CMD_ADD_SUS_PATH_UID: libc::c_long = 0x55554;
const CMD_SHOW_VERSION: libc::c_long = 0x555e1;

const MAX_LEN_PATHNAME: usize = 256;
const NEW_UTS_LEN: usize = 64;
const FAKE_CMDLINE_SIZE: usize = 8192;

// kstat spoof flags (mirror susfs.h; CTIME_TV_SEC fixed to (1<<8))
const KSTAT_SPOOF_ATIME_TV_SEC: i32 = 1 << 4;
const KSTAT_SPOOF_MTIME_TV_SEC: i32 = 1 << 6;
const KSTAT_SPOOF_CTIME_TV_SEC: i32 = 1 << 8;

const SUSFS_PLAN_PATH: &str = "/data/adb/susfs/per_app.json";

#[inline]
fn susfs_call<T>(cmd: libc::c_long, arg: *mut T) -> i32 {
    unsafe {
        libc::syscall(libc::SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, cmd, arg) as i32
    }
}

fn copy_str(dst: &mut [u8], src: &str) {
    let b = src.as_bytes();
    let n = b.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&b[..n]);
    dst[n] = 0;
}

#[repr(C)]
struct StSusKstat {
    is_statically: i32,
    target_ino: u64,
    target_pathname: [u8; MAX_LEN_PATHNAME],
    spoofed_ino: u64,
    spoofed_dev: u64,
    spoofed_nlink: u32,
    spoofed_size: i64,
    spoofed_atime_tv_sec: i64,
    spoofed_atime_tv_nsec: u64,
    spoofed_mtime_tv_sec: i64,
    spoofed_mtime_tv_nsec: u64,
    spoofed_ctime_tv_sec: i64,
    spoofed_ctime_tv_nsec: u64,
    spoofed_blocks: i64,
    spoofed_blksize: i64,
    flags: i32,
    err: i32,
    target_uid: i32,
}

#[repr(C)]
struct StOpenRedirect {
    target_pathname: [u8; MAX_LEN_PATHNAME],
    redirected_pathname: [u8; MAX_LEN_PATHNAME],
    uid_scheme: i32,
    err: i32,
    target_uid: i32,
}

#[repr(C)]
struct StUname {
    release: [u8; NEW_UTS_LEN + 1],
    version: [u8; NEW_UTS_LEN + 1],
    err: i32,
    target_uid: i32,
}

#[repr(C)]
struct StCmdline {
    fake: [u8; FAKE_CMDLINE_SIZE],
    err: i32,
    target_uid: i32,
}

#[repr(C)]
struct StSusPath {
    target_pathname: [u8; MAX_LEN_PATHNAME],
    err: i32,
    target_uid: i32,
}

// New feature (not a *_UID variant): target_uid is FIRST here, matching the kernel
// struct st_susfs_file_time_offset { int target_uid; long offset_sec; int err; }.
#[repr(C)]
struct StFileTimeOffset {
    target_uid: i32,
    offset_sec: i64,
    err: i32,
}

// struct st_susfs_uptime_offset { int target_uid; long offset_sec; int err; }.
#[repr(C)]
struct StUptimeOffset {
    target_uid: i32,
    offset_sec: i64,
    err: i32,
}

/// Back-date a path's timestamps for one uid. Stats the real inode so the kernel
/// entry matches, then spoofs atime/mtime/ctime seconds.
fn kstat_backdate(uid: i32, path: &str, mtime: i64, ctime: i64) {
    let md = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return, // path may not exist yet; skip
    };
    let mut k: StSusKstat = unsafe { std::mem::zeroed() };
    k.is_statically = 1;
    k.target_ino = md.ino();
    copy_str(&mut k.target_pathname, path);
    k.spoofed_ino = md.ino();
    k.spoofed_dev = md.dev();
    k.spoofed_nlink = md.nlink() as u32;
    k.spoofed_size = md.size() as i64;
    k.spoofed_atime_tv_sec = mtime;
    k.spoofed_mtime_tv_sec = mtime;
    k.spoofed_ctime_tv_sec = ctime;
    k.spoofed_blocks = md.blocks() as i64;
    k.spoofed_blksize = md.blksize() as i64;
    k.flags = KSTAT_SPOOF_ATIME_TV_SEC | KSTAT_SPOOF_MTIME_TV_SEC | KSTAT_SPOOF_CTIME_TV_SEC;
    k.target_uid = uid;
    susfs_call(CMD_ADD_SUS_KSTAT_STATICALLY_UID, &mut k);
}

fn set_uname(uid: i32, release: &str, version: &str) {
    let mut u: StUname = unsafe { std::mem::zeroed() };
    copy_str(&mut u.release, release);
    copy_str(&mut u.version, version);
    u.target_uid = uid;
    susfs_call(CMD_SET_UNAME_UID, &mut u);
}

fn set_cmdline_file(uid: i32, file: &str) {
    let data = match fs::read(file) {
        Ok(d) => d,
        Err(_) => return,
    };
    if data.len() >= FAKE_CMDLINE_SIZE {
        return;
    }
    let mut c: Box<StCmdline> = unsafe { Box::new(std::mem::zeroed()) };
    let n = data.len();
    c.fake[..n].copy_from_slice(&data[..n]);
    c.fake[n] = 0;
    c.target_uid = uid;
    susfs_call(CMD_SET_CMDLINE_OR_BOOTCONFIG_UID, &mut *c);
}

fn open_redirect(uid: i32, target: &str, redirect: &str) {
    // uid_scheme 3 == umounted apps (uid >= 10000); required for target apps.
    let mut o: StOpenRedirect = unsafe { std::mem::zeroed() };
    copy_str(&mut o.target_pathname, target);
    copy_str(&mut o.redirected_pathname, redirect);
    o.uid_scheme = 3;
    o.target_uid = uid;
    susfs_call(CMD_ADD_OPEN_REDIRECT_UID, &mut o);
}

fn sus_path(uid: i32, path: &str) {
    let mut p: StSusPath = unsafe { std::mem::zeroed() };
    copy_str(&mut p.target_pathname, path);
    p.target_uid = uid;
    susfs_call(CMD_ADD_SUS_PATH_UID, &mut p);
}

/// Shift every timestamp of files the app OWNS by `offset_sec` (signed).
fn set_file_time_offset(uid: i32, offset_sec: i64) {
    let mut o = StFileTimeOffset { target_uid: uid, offset_sec, err: 0 };
    susfs_call(CMD_SET_FILE_TIME_OFFSET_UID, &mut o);
}

/// Shift the uptime this uid sees (/proc/uptime + sysinfo(2)) by `offset_sec` (signed).
fn set_uptime_offset(uid: i32, offset_sec: i64) {
    let mut o = StUptimeOffset { target_uid: uid, offset_sec, err: 0 };
    susfs_call(CMD_SET_UPTIME_OFFSET_UID, &mut o);
}

/// Query susfs version via the (uid-0) show-version command. Non-empty => integrated.
pub fn susfs_version() -> Option<String> {
    #[repr(C)]
    struct StVersion {
        version: [u8; 16],
        err: i32,
    }
    let mut v: StVersion = unsafe { std::mem::zeroed() };
    susfs_call(CMD_SHOW_VERSION, &mut v);
    if v.err != 0 || v.version[0] == 0 {
        return None;
    }
    let end = v.version.iter().position(|&b| b == 0).unwrap_or(v.version.len());
    Some(String::from_utf8_lossy(&v.version[..end]).into_owned())
}

/// Apply the whole per-app plan. Called once at post-fs-data.
pub fn apply_plan() {
    // post-fs-data: the settings provider isn't up yet, so read the cached file
    // (written by apply_from_settings on a previous boot).
    if let Ok(raw) = fs::read_to_string(SUSFS_PLAN_PATH) {
        apply_plan_json(&raw);
    }
}

/// boot-completed: pull the framework-generated plan from Settings (system_server
/// is up now), cache it to the plan file for next boot's post-fs-data, and apply.
pub fn apply_from_settings() {
    if let Ok(o) = std::process::Command::new("settings")
        .args(["get", "secure", "per_apps_susfs_plan"])
        .output()
    {
        let raw = String::from_utf8_lossy(&o.stdout);
        let raw = raw.trim();
        if raw.starts_with('{') {
            let _ = fs::create_dir_all("/data/adb/susfs");
            let _ = fs::write(SUSFS_PLAN_PATH, raw);
            apply_plan_json(raw);
        }
    }
}

fn apply_plan_json(raw: &str) {
    let plan: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("susfs: bad plan json: {e}");
            return;
        }
    };
    let apps = match plan.get("apps").and_then(|a| a.as_array()) {
        Some(a) => a,
        None => return,
    };
    for app in apps {
        let uid = match app.get("uid").and_then(|u| u.as_i64()) {
            Some(u) => u as i32,
            None => continue,
        };
        // Comprehensive: shift ALL of the app's own files by a per-uid delta
        // (covers files created after boot). Preferred over the per-inode kstat list.
        if let Some(off) = app.get("file_time_offset").and_then(|o| o.as_i64()) {
            if off != 0 {
                set_file_time_offset(uid, off);
            }
        }
        // Kernel-side /proc/uptime + sysinfo() spoof (replaces the bionic uptime offset).
        if let Some(off) = app.get("uptime_offset").and_then(|o| o.as_i64()) {
            if off != 0 {
                set_uptime_offset(uid, off);
            }
        }
        if let Some(kstat) = app.get("kstat").and_then(|k| k.as_array()) {
            for e in kstat {
                let path = e.get("path").and_then(|p| p.as_str()).unwrap_or("");
                let mtime = e.get("mtime").and_then(|m| m.as_i64()).unwrap_or(0);
                let ctime = e.get("ctime").and_then(|c| c.as_i64()).unwrap_or(0);
                if !path.is_empty() && ctime > 0 {
                    kstat_backdate(uid, path, mtime, ctime);
                }
            }
        }
        if let Some(un) = app.get("uname") {
            let rel = un.get("release").and_then(|r| r.as_str()).unwrap_or("");
            let ver = un.get("version").and_then(|v| v.as_str()).unwrap_or("");
            if !rel.is_empty() && !ver.is_empty() {
                set_uname(uid, rel, ver);
            }
        }
        if let Some(cl) = app.get("cmdline_file").and_then(|c| c.as_str()) {
            set_cmdline_file(uid, cl);
        }
        if let Some(reds) = app.get("redirects").and_then(|r| r.as_array()) {
            for r in reds {
                let t = r.get("target").and_then(|x| x.as_str()).unwrap_or("");
                let d = r.get("redirect").and_then(|x| x.as_str()).unwrap_or("");
                if !t.is_empty() && !d.is_empty() {
                    open_redirect(uid, t, d);
                }
            }
        }
        if let Some(hides) = app.get("hide").and_then(|h| h.as_array()) {
            for h in hides {
                if let Some(p) = h.as_str() {
                    sus_path(uid, p);
                }
            }
        }
    }
}

/// Stamp KernelSU + SusFS integration status into system-only properties for the
/// Settings UI. KernelSU presence is implied (this daemon runs), version from the
/// KSU driver; SusFS from the version query.
pub fn stamp_status() {
    let rp = prop_rs_android::resetprop::ResetProp {
        skip_svc: true,
        persistent: false,
        persist_only: false,
        verbose: false,
        show_context: false,
        rebuild: false,
    };
    let ksu = crate::ksucalls::get_version();
    let _ = rp.set("sys.mist.ksu.version", &ksu.to_string());
    match susfs_version() {
        Some(v) => {
            let _ = rp.set("sys.mist.susfs.integrated", "1");
            let _ = rp.set("sys.mist.susfs.version", &v);
        }
        None => {
            let _ = rp.set("sys.mist.susfs.integrated", "0");
        }
    }
}
