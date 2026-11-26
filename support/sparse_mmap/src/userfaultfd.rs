// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A safe wrapper around Linux `userfaultfd`, used to populate shared memory
//! lazily on first access.
//!
//! Only "missing page" faults are supported: registering a range makes any
//! access to a page that is not yet present block until it is resolved with
//! [`Userfaultfd::copy`], [`Userfaultfd::zeropage`], or
//! [`Userfaultfd::poison`]. The resolving ioctls only ever install pages that
//! are missing, so they can never overwrite data that is already present.

#![cfg(target_os = "linux")]
#![cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]

use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

// Constants and structures from `include/uapi/linux/userfaultfd.h`. The ioctl
// numbers use the generic encoding shared by x86_64 and aarch64.

const UFFDIO: u64 = 0xaa;
const UFFD_API: u64 = 0xaa;

const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;

const fn ioc(dir: u64, nr: u64, size: usize) -> u64 {
    (dir << 30) | ((size as u64) << 16) | (UFFDIO << 8) | nr
}

const USERFAULTFD_IOC_NEW: u64 = ioc(0, 0x00, 0);
const UFFDIO_API: u64 = ioc(IOC_READ | IOC_WRITE, 0x3f, size_of::<UffdioApi>());
const UFFDIO_REGISTER: u64 = ioc(IOC_READ | IOC_WRITE, 0x00, size_of::<UffdioRegister>());
const UFFDIO_WAKE: u64 = ioc(IOC_READ, 0x02, size_of::<UffdioRange>());
const UFFDIO_COPY: u64 = ioc(IOC_READ | IOC_WRITE, 0x03, size_of::<UffdioCopy>());
const UFFDIO_ZEROPAGE: u64 = ioc(IOC_READ | IOC_WRITE, 0x04, size_of::<UffdioZeropage>());
const UFFDIO_POISON: u64 = ioc(IOC_READ | IOC_WRITE, 0x08, size_of::<UffdioPoison>());

const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
const UFFD_PAGEFAULT_FLAG_WRITE: u64 = 1 << 0;
const UFFD_USER_MODE_ONLY: libc::c_int = 1;

/// Bits in the `ioctls` mask returned by `UFFDIO_REGISTER`.
const IOCTL_WAKE: u64 = 1 << 0x02;
const IOCTL_COPY: u64 = 1 << 0x03;
const IOCTL_ZEROPAGE: u64 = 1 << 0x04;
const IOCTL_POISON: u64 = 1 << 0x08;

#[repr(C)]
#[derive(Default)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[repr(C)]
#[derive(Default)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
#[derive(Default)]
struct UffdioRegister {
    range: UffdioRange,
    mode: u64,
    ioctls: u64,
}

#[repr(C)]
#[derive(Default)]
struct UffdioCopy {
    dst: u64,
    src: u64,
    len: u64,
    mode: u64,
    copy: i64,
}

#[repr(C)]
#[derive(Default)]
struct UffdioZeropage {
    range: UffdioRange,
    mode: u64,
    zeropage: i64,
}

#[repr(C)]
#[derive(Default)]
struct UffdioPoison {
    range: UffdioRange,
    mode: u64,
    updated: i64,
}

#[repr(C)]
#[derive(Default)]
struct UffdMsg {
    event: u8,
    reserved1: u8,
    reserved2: u16,
    reserved3: u32,
    pagefault_flags: u64,
    pagefault_address: u64,
    pagefault_feat: u64,
}

const _: () = assert!(size_of::<UffdMsg>() == 32);

/// Optional `userfaultfd` features.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Features(u64);

impl Features {
    /// No optional features.
    pub const NONE: Self = Self(0);
    /// Missing-page faults on shared memory (memfd, tmpfs).
    pub const MISSING_SHMEM: Self = Self(1 << 5);
    /// `UFFDIO_POISON` support.
    pub const POISON: Self = Self(1 << 14);

    /// Returns whether all features in `other` are set in `self`.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Features {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Which faults a [`Userfaultfd`] handles.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FaultScope {
    /// Faults from both user mode and the kernel (for example, KVM accessing
    /// guest memory). Requires access to `/dev/userfaultfd`, or the
    /// `vm.unprivileged_userfaultfd` sysctl, or `CAP_SYS_PTRACE`.
    All,
    /// Faults from user mode only. Kernel accesses to a missing page fail
    /// instead of waiting. Available to unprivileged processes.
    UserModeOnly,
}

/// A page fault reported by a [`Userfaultfd`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PageFault {
    /// The faulting address, rounded down to the page size.
    pub address: usize,
    /// Whether the access was a write.
    pub write: bool,
}

/// The result of resolving a fault with a page-installing ioctl.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// All pages in the range were installed.
    All,
    /// A page was already present. Only the first `installed` bytes were
    /// installed; the page at that offset was present and left unchanged.
    AlreadyPresent {
        /// The number of bytes installed before the present page.
        installed: usize,
    },
}

/// A `userfaultfd` object.
#[derive(Debug)]
pub struct Userfaultfd {
    fd: OwnedFd,
    features: Features,
}

impl Userfaultfd {
    /// Returns the features supported by the running kernel for `scope`.
    pub fn supported_features(scope: FaultScope) -> io::Result<Features> {
        // The API handshake can only be done once per object, so probe with a
        // throwaway object.
        let fd = open(scope)?;
        let api = api(fd.as_fd(), 0)?;
        Ok(Features(api.features))
    }

    /// Creates a new object for `scope` with the given required features.
    ///
    /// Fails with [`io::ErrorKind::Unsupported`] if the kernel does not support
    /// one of the features.
    pub fn new(scope: FaultScope, features: Features) -> io::Result<Self> {
        let fd = open(scope)?;
        let api = api(fd.as_fd(), features.0)?;
        if !Features(api.features).contains(features) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "userfaultfd features are not supported by the kernel",
            ));
        }
        Ok(Self { fd, features })
    }

    /// Registers `len` bytes at `address` for missing-page faults.
    ///
    /// After this returns, any access to a page in the range that is not
    /// present blocks until the fault is resolved through this object.
    ///
    /// # Safety
    /// Resolving a fault installs caller-chosen data into a missing page of
    /// the range. The caller must ensure that no Rust object relies on the
    /// contents of missing pages in the range (for example, by only
    /// registering mappings that are accessed through raw pointers, such as
    /// guest memory).
    pub unsafe fn register(&self, address: usize, len: usize) -> io::Result<()> {
        let mut register = UffdioRegister {
            range: range(address, len),
            mode: UFFDIO_REGISTER_MODE_MISSING,
            ioctls: 0,
        };
        // SAFETY: the argument is a valid `uffdio_register` that outlives the
        // call. Registering only changes how faults in the range are handled.
        unsafe { ioctl(self.fd.as_fd(), UFFDIO_REGISTER, &mut register) }?;
        let mut required = IOCTL_WAKE | IOCTL_COPY | IOCTL_ZEROPAGE;
        if self.features.contains(Features::POISON) {
            required |= IOCTL_POISON;
        }
        if register.ioctls & required != required {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "userfaultfd does not support the required operations for this memory",
            ));
        }
        Ok(())
    }

    /// Installs a copy of `data` at the registered, page-aligned `address`,
    /// waking any thread waiting on the range.
    pub fn copy(&self, address: usize, data: &[u8]) -> io::Result<Resolved> {
        let mut installed = 0;
        loop {
            let mut copy = UffdioCopy {
                dst: (address + installed) as u64,
                src: data[installed..].as_ptr() as u64,
                len: (data.len() - installed) as u64,
                mode: 0,
                copy: 0,
            };
            // SAFETY: `src` points to `len` readable bytes of `data`. The
            // kernel only installs pages that are missing in a range registered
            // with this object, so no existing memory is modified.
            let r = unsafe { ioctl(self.fd.as_fd(), UFFDIO_COPY, &mut copy) };
            if copy.copy > 0 {
                installed += copy.copy as usize;
            }
            match r {
                Ok(()) => return Ok(Resolved::All),
                Err(err) => match err.raw_os_error() {
                    Some(libc::EEXIST) => return Ok(Resolved::AlreadyPresent { installed }),
                    Some(libc::EAGAIN) => continue,
                    _ => return Err(err),
                },
            }
        }
    }

    /// Installs zero pages at the registered, page-aligned range, waking any
    /// thread waiting on it.
    pub fn zeropage(&self, address: usize, len: usize) -> io::Result<Resolved> {
        let mut installed = 0;
        loop {
            let mut zeropage = UffdioZeropage {
                range: range(address + installed, len - installed),
                mode: 0,
                zeropage: 0,
            };
            // SAFETY: the kernel only installs zero pages where pages are
            // missing in a range registered with this object.
            let r = unsafe { ioctl(self.fd.as_fd(), UFFDIO_ZEROPAGE, &mut zeropage) };
            if zeropage.zeropage > 0 {
                installed += zeropage.zeropage as usize;
            }
            match r {
                Ok(()) => return Ok(Resolved::All),
                Err(err) => match err.raw_os_error() {
                    Some(libc::EEXIST) => return Ok(Resolved::AlreadyPresent { installed }),
                    Some(libc::EAGAIN) => continue,
                    _ => return Err(err),
                },
            }
        }
    }

    /// Marks the registered, page-aligned range as poisoned, waking any thread
    /// waiting on it. Later accesses fail with `SIGBUS` (or an error for
    /// kernel accesses) instead of seeing data.
    ///
    /// Requires [`Features::POISON`].
    pub fn poison(&self, address: usize, len: usize) -> io::Result<Resolved> {
        let mut installed = 0;
        loop {
            let mut poison = UffdioPoison {
                range: range(address + installed, len - installed),
                mode: 0,
                updated: 0,
            };
            // SAFETY: the kernel only installs poison markers where pages are
            // missing in a range registered with this object.
            let r = unsafe { ioctl(self.fd.as_fd(), UFFDIO_POISON, &mut poison) };
            if poison.updated > 0 {
                installed += poison.updated as usize;
            }
            match r {
                Ok(()) => return Ok(Resolved::All),
                Err(err) => match err.raw_os_error() {
                    Some(libc::EEXIST) => return Ok(Resolved::AlreadyPresent { installed }),
                    Some(libc::EAGAIN) => continue,
                    _ => return Err(err),
                },
            }
        }
    }

    /// Wakes threads waiting on faults in the range, so that they retry the
    /// access.
    pub fn wake(&self, address: usize, len: usize) -> io::Result<()> {
        let mut range = range(address, len);
        // SAFETY: the argument is a valid `uffdio_range`. Waking has no effect
        // on memory contents.
        unsafe { ioctl(self.fd.as_fd(), UFFDIO_WAKE, &mut range) }
    }

    /// Reads the next pending page fault, or returns `None` if there is none.
    ///
    /// Non-fault events are skipped.
    pub fn read_fault(&self) -> io::Result<Option<PageFault>> {
        loop {
            let mut msg = UffdMsg::default();
            // SAFETY: `msg` is a valid buffer of `size_of::<UffdMsg>()` bytes.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    std::ptr::from_mut(&mut msg).cast(),
                    size_of::<UffdMsg>(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                return match err.kind() {
                    io::ErrorKind::WouldBlock => Ok(None),
                    io::ErrorKind::Interrupted => continue,
                    _ => Err(err),
                };
            }
            if n as usize != size_of::<UffdMsg>() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short read from userfaultfd",
                ));
            }
            if msg.event != UFFD_EVENT_PAGEFAULT {
                continue;
            }
            return Ok(Some(PageFault {
                address: msg.pagefault_address as usize,
                write: msg.pagefault_flags & UFFD_PAGEFAULT_FLAG_WRITE != 0,
            }));
        }
    }

    /// Waits until a fault is pending or `stop` is signaled. Returns `false`
    /// if `stop` was signaled.
    pub fn wait(&self, stop: &StopEvent) -> io::Result<bool> {
        let mut fds = [
            libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            // SAFETY: `fds` is a valid array of `pollfd` for the duration of
            // the call.
            let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if fds[1].revents != 0 {
                return Ok(false);
            }
            if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("userfaultfd poll error"));
            }
            if fds[0].revents != 0 {
                return Ok(true);
            }
        }
    }

    /// Returns the features enabled on this object.
    pub fn features(&self) -> Features {
        self.features
    }
}

/// An event used to stop [`Userfaultfd::wait`]. Once signaled, it stays
/// signaled.
#[derive(Debug)]
pub struct StopEvent {
    fd: OwnedFd,
}

impl StopEvent {
    /// Creates a new, unsignaled event.
    pub fn new() -> io::Result<Self> {
        // SAFETY: `eventfd` has no memory safety requirements.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a newly created, owned file descriptor.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Signals the event.
    pub fn signal(&self) {
        let value: u64 = 1;
        // SAFETY: writes 8 bytes from a valid `u64`. A full counter only
        // means the event is already signaled.
        unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                std::ptr::from_ref(&value).cast(),
                size_of::<u64>(),
            );
        }
    }
}

fn range(address: usize, len: usize) -> UffdioRange {
    UffdioRange {
        start: address as u64,
        len: len as u64,
    }
}

fn open(scope: FaultScope) -> io::Result<OwnedFd> {
    let flags = libc::O_CLOEXEC | libc::O_NONBLOCK;
    if scope == FaultScope::All {
        // Prefer `/dev/userfaultfd`, whose access is controlled by file
        // permissions, before falling back to the syscall.
        if let Ok(dev) = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/userfaultfd")
        {
            // SAFETY: `USERFAULTFD_IOC_NEW` takes the flags by value and
            // returns a new file descriptor.
            let fd = unsafe {
                libc::ioctl(
                    dev.as_raw_fd(),
                    USERFAULTFD_IOC_NEW as libc::Ioctl,
                    flags as libc::c_ulong,
                )
            };
            if fd >= 0 {
                // SAFETY: `fd` is a newly created, owned file descriptor.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    let flags = match scope {
        FaultScope::All => flags,
        FaultScope::UserModeOnly => flags | UFFD_USER_MODE_ONLY,
    };
    // SAFETY: the `userfaultfd` syscall takes flags by value and returns a new
    // file descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_userfaultfd, flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a newly created, owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

fn api(fd: BorrowedFd<'_>, features: u64) -> io::Result<UffdioApi> {
    let mut api = UffdioApi {
        api: UFFD_API,
        features,
        ioctls: 0,
    };
    // SAFETY: the argument is a valid `uffdio_api` that outlives the call.
    unsafe { ioctl(fd, UFFDIO_API, &mut api) }?;
    Ok(api)
}

/// Issues an ioctl that takes a pointer to `arg`.
///
/// # Safety
/// `request` must be an ioctl whose argument is a `T`, and its effect must be
/// memory safe for the caller's arguments.
unsafe fn ioctl<T>(fd: BorrowedFd<'_>, request: u64, arg: &mut T) -> io::Result<()> {
    // SAFETY: guaranteed by the caller.
    let r = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            request as libc::Ioctl,
            std::ptr::from_mut(arg),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SparseMapping;
    use crate::alloc_shared_memory;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    fn new_uffd() -> Option<Userfaultfd> {
        match Userfaultfd::new(FaultScope::UserModeOnly, Features::MISSING_SHMEM) {
            Ok(uffd) => Some(uffd),
            Err(err) => {
                // Some kernels or sandboxes disable userfaultfd entirely.
                eprintln!("skipping: userfaultfd unavailable: {err}");
                None
            }
        }
    }

    #[test]
    fn missing_shmem_fault_is_resolved_by_copy() {
        let Some(uffd) = new_uffd() else { return };
        let page = SparseMapping::page_size();
        let memfd = alloc_shared_memory(2 * page, "uffd-test").unwrap();
        let mapping = SparseMapping::new(2 * page).unwrap();
        mapping.map_file(0, 2 * page, &memfd, 0, true).unwrap();
        let base = mapping.as_ptr() as usize;
        // SAFETY: the mapping is only accessed through `SparseMapping`.
        unsafe { uffd.register(base, 2 * page) }.unwrap();

        let uffd = Arc::new(uffd);
        let stop = Arc::new(StopEvent::new().unwrap());
        let done = Arc::new(AtomicBool::new(false));
        let handler = std::thread::spawn({
            let uffd = uffd.clone();
            let stop = stop.clone();
            let done = done.clone();
            move || {
                while uffd.wait(&stop).unwrap() {
                    while let Some(fault) = uffd.read_fault().unwrap() {
                        let data = vec![((fault.address - base) / page + 1) as u8; page];
                        assert_eq!(uffd.copy(fault.address, &data).unwrap(), Resolved::All);
                    }
                    if done.load(Ordering::Acquire) {
                        break;
                    }
                }
            }
        });

        // Read the second page: the handler fills it with 2s.
        let mut buf = vec![0; page];
        mapping.read_at(page, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 2));

        // A copy over a present page reports it and leaves it unchanged.
        assert_eq!(
            uffd.copy(base + page, &vec![9; page]).unwrap(),
            Resolved::AlreadyPresent { installed: 0 }
        );
        mapping.read_at(page, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 2));

        done.store(true, Ordering::Release);
        stop.signal();
        handler.join().unwrap();
    }

    #[test]
    fn zeropage_fills_missing_only() {
        let Some(uffd) = new_uffd() else { return };
        let page = SparseMapping::page_size();
        let memfd = alloc_shared_memory(2 * page, "uffd-test").unwrap();
        let mapping = SparseMapping::new(2 * page).unwrap();
        mapping.map_file(0, 2 * page, &memfd, 0, true).unwrap();
        let base = mapping.as_ptr() as usize;
        // SAFETY: the mapping is only accessed through `SparseMapping`.
        unsafe { uffd.register(base, 2 * page) }.unwrap();

        assert_eq!(uffd.copy(base, &vec![7; page]).unwrap(), Resolved::All);
        assert_eq!(
            uffd.zeropage(base, 2 * page).unwrap(),
            Resolved::AlreadyPresent { installed: 0 }
        );
        assert_eq!(uffd.zeropage(base + page, page).unwrap(), Resolved::All);

        let mut buf = vec![0; 2 * page];
        mapping.read_at(0, &mut buf).unwrap();
        assert!(buf[..page].iter().all(|&b| b == 7));
        assert!(buf[page..].iter().all(|&b| b == 0));
    }
}
